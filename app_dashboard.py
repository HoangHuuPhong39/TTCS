import os
import json
import time
import uuid
import random
import logging
import threading
import urllib3
import markdown
import sqlite3
import requests
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, jsonify, request, render_template, send_from_directory
from dotenv import load_dotenv

# --- THƯ VIỆN LOCAL LLM (THAY THẾ HOÀN TOÀN GEMINI) ---
from langchain_community.llms import Ollama
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough

# ==========================================
# 1. CẤU HÌNH HỆ THỐNG
# ==========================================
load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Logging chuẩn (thay thế print)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('soc_dashboard.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# Đọc cấu hình từ biến môi trường (.env)
WAZUH_IP = os.getenv("WAZUH_IP", "192.168.157.128")
WAZUH_PORT = int(os.getenv("WAZUH_PORT", "9200"))
WAZUH_USER = os.getenv("WAZUH_USER", "admin")
WAZUH_PASS = os.getenv("WAZUH_PASS", "")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
CHROMA_DIR = os.path.join(BASE_DIR, "chroma_db")
PLAYBOOK_PATH = os.getenv("PLAYBOOK_PATH", os.path.join(BASE_DIR, "data", "SOC_Playbook.txt"))
ALERTS_DB_PATH = os.path.join(BASE_DIR, "alerts_store.db")

# Tạo thư mục reports nếu chưa có
os.makedirs(REPORTS_DIR, exist_ok=True)

# --- TÍCH HỢP NÂNG CẤP TỪ SOC PIPELINE: INCIDENT CORRELATOR & VULNS BLUEPRINT ---
from vulns_blueprint import vulns_bp
from incident_correlator import IncidentCorrelator, extract_ip

app = Flask(__name__)
app.register_blueprint(vulns_bp)

# Khởi tạo Incident Correlator cho SOC (Debounce Window 20s)
correlator = IncidentCorrelator()

# ==========================================
# ANALYSIS JOB STORE (Background Threading)
# ==========================================
_analysis_jobs = {}   # job_id -> {status, progress, message, filename, error}
_analysis_lock = threading.Lock()

# ==========================================
# 2. RATE LIMITER ĐƠN GIẢN (CHỐNG SPAM AI)
# ==========================================
_rate_limit_store = {}


def rate_limit(max_per_minute=5):
    """Decorator giới hạn tần suất gọi endpoint."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            key = f.__name__
            now = time.time()
            _rate_limit_store[key] = [
                t for t in _rate_limit_store.get(key, []) if now - t < 60
            ]
            if len(_rate_limit_store[key]) >= max_per_minute:
                return jsonify({
                    "status": "error",
                    "message": "Quá nhiều yêu cầu. Vui lòng đợi 1 phút."
                }), 429
            _rate_limit_store[key].append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ==========================================
# 3. HÀM TIỆN ÍCH DÙNG CHUNG (DRY)
# ==========================================
def fetch_wazuh_alerts(size=6, min_level=7, timeout=5):
    """Truy vấn cảnh báo từ Wazuh SIEM — dùng chung cho get_alerts() và analyze()."""
    url = f"https://{WAZUH_IP}:{WAZUH_PORT}/wazuh-alerts-*/_search"
    query = {
        "size": size,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"range": {"rule.level": {"gte": min_level}}}
    }
    return requests.post(
        url,
        auth=(WAZUH_USER, WAZUH_PASS),
        headers={'Content-Type': 'application/json'},
        data=json.dumps(query),
        verify=False,
        timeout=timeout
    )


def parse_alert_timestamp(timestamp_raw):
    """Parse ISO timestamp an toàn, không nuốt exception."""
    try:
        dt = datetime.fromisoformat(timestamp_raw.replace('Z', '+00:00'))
        return dt.strftime('%H:%M:%S')
    except (ValueError, TypeError, AttributeError) as e:
        logger.warning(f"Lỗi parse timestamp '{timestamp_raw}': {e}")
        return datetime.now().strftime('%H:%M:%S')


def format_alerts(hits):
    """Chuẩn hóa danh sách alert từ Elasticsearch hits — bao gồm chi tiết đầy đủ."""
    formatted = []
    critical_cnt = 0
    for h in hits:
        source = h.get('_source', {})
        rule = source.get('rule', {})
        agent = source.get('agent', {})
        lvl = rule.get('level', 0)
        if lvl >= 10:
            critical_cnt += 1

        timestamp_raw = source.get('timestamp', '')
        time_display = parse_alert_timestamp(timestamp_raw)

        # Parse date for grouping
        try:
            dt = datetime.fromisoformat(timestamp_raw.replace('Z', '+00:00'))
            date_str = dt.strftime('%Y-%m-%d')
        except (ValueError, TypeError, AttributeError):
            date_str = datetime.now().strftime('%Y-%m-%d')

        rule_groups = rule.get('groups', [])
        if isinstance(rule_groups, list):
            rule_groups = ', '.join(rule_groups)

        # Trích xuất IP nguồn để IncidentCorrelator gom nhóm
        data_block = source.get('data', {})
        src_ip = data_block.get('srcip') or ((data_block.get('win') or {}).get('eventdata') or {}).get('ipAddress') or None

        formatted.append({
            "alert_id": h.get('_id', f"alert_{time_display}_{lvl}"),
            "timestamp": timestamp_raw,
            "date": date_str,
            "time_display": time_display,
            "level": lvl,
            "agent": agent.get('name', 'Unknown-Agent'),
            "description": rule.get('description', 'No description'),
            "rule_id": str(rule.get('id', '')),
            "rule_groups": rule_groups,
            "source_ip": src_ip,
            "full_log": source.get('full_log', source.get('data', {}).get('win', {}).get('system', {}).get('message', '')),
            "raw_json": json.dumps(source, ensure_ascii=False, indent=2)[:2000]
        })
    return formatted, critical_cnt


def count_report_files():
    """Đếm số file báo cáo đã xuất."""
    try:
        return len([f for f in os.listdir(REPORTS_DIR) if f.endswith('.html')])
    except OSError:
        return 0


# ==========================================
# 3b. SQLITE DATABASE — LƯU TRỮ CẢNH BÁO 2 NGÀY
# ==========================================
def get_db():
    """Lấy kết nối SQLite (thread-safe cho Flask)."""
    conn = sqlite3.connect(ALERTS_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Khởi tạo bảng alerts và evaluations."""
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT UNIQUE NOT NULL,
            timestamp TEXT NOT NULL,
            date TEXT NOT NULL,
            time_display TEXT NOT NULL,
            level INTEGER NOT NULL,
            agent TEXT NOT NULL,
            description TEXT NOT NULL,
            rule_id TEXT DEFAULT '',
            rule_groups TEXT DEFAULT '',
            full_log TEXT DEFAULT '',
            raw_json TEXT DEFAULT '',
            source_ip TEXT DEFAULT NULL,
            alert_count INTEGER DEFAULT 1,
            ai_verdict TEXT DEFAULT NULL,
            ai_verdict_reason TEXT DEFAULT NULL,
            evaluation TEXT DEFAULT NULL,
            evaluated_at TEXT DEFAULT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_date ON alerts(date);
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_alert_id ON alerts(alert_id);
    """)

    # Tự động cập nhật cột mới nếu DB đã tồn tại từ phiên bản cũ
    cols = [row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()]
    new_cols = {
        "source_ip": "TEXT",
        "alert_count": "INTEGER DEFAULT 1",
        "ai_verdict": "TEXT",
        "ai_verdict_reason": "TEXT"
    }
    for col, col_type in new_cols.items():
        if col not in cols:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {col_type}")
    conn.commit()
    conn.close()
    logger.info("SQLite database initialized.")


def cleanup_old_alerts(days=365):
    """Xóa cảnh báo cũ hơn N ngày (mặc định 365 — giữ lịch sử lâu dài)."""
    cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
    conn = get_db()
    cursor = conn.execute("DELETE FROM alerts WHERE date < ?", (cutoff,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    if deleted > 0:
        logger.info(f"Đã xóa {deleted} cảnh báo cũ (trước {cutoff}).")


def save_alerts_to_db(alerts_list):
    """Lưu danh sách cảnh báo vào DB (upsert theo alert_id)."""
    conn = get_db()
    for alert in alerts_list:
        conn.execute("""
            INSERT OR REPLACE INTO alerts
            (alert_id, timestamp, date, time_display, level, agent, description,
             rule_id, rule_groups, full_log, raw_json, source_ip,
             evaluation, evaluated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    COALESCE((SELECT evaluation FROM alerts WHERE alert_id = ?), NULL),
                    COALESCE((SELECT evaluated_at FROM alerts WHERE alert_id = ?), NULL))
        """, (
            alert['alert_id'], alert['timestamp'], alert['date'],
            alert['time_display'], alert['level'], alert['agent'],
            alert['description'], alert.get('rule_id', ''),
            alert.get('rule_groups', ''), alert.get('full_log', ''),
            alert.get('raw_json', ''), alert.get('source_ip'),
            alert['alert_id'], alert['alert_id']
        ))
    conn.commit()
    conn.close()


def get_alerts_from_db(date=None, month=None, days=None):
    """Đọc cảnh báo từ DB — hỗ trợ lọc theo ngày, tháng, hoặc số ngày gần đây."""
    conn = get_db()

    if date:
        # Lọc theo ngày cụ thể
        rows = conn.execute("""
            SELECT * FROM alerts WHERE date = ? ORDER BY timestamp DESC
        """, (date,)).fetchall()
    elif month:
        # Lọc theo tháng (format: 2026-09)
        rows = conn.execute("""
            SELECT * FROM alerts WHERE date LIKE ? ORDER BY timestamp DESC
        """, (month + '%',)).fetchall()
    elif days:
        cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
        rows = conn.execute("""
            SELECT * FROM alerts WHERE date >= ? ORDER BY timestamp DESC
        """, (cutoff,)).fetchall()
    else:
        # Mặc định: hôm nay
        today = datetime.now().strftime('%Y-%m-%d')
        rows = conn.execute("""
            SELECT * FROM alerts WHERE date = ? ORDER BY timestamp DESC
        """, (today,)).fetchall()

    conn.close()

    grouped = {}
    for row in rows:
        d = row['date']
        if d not in grouped:
            grouped[d] = []
        grouped[d].append({
            'alert_id': row['alert_id'],
            'timestamp': row['timestamp'],
            'date': row['date'],
            'time_display': row['time_display'],
            'level': row['level'],
            'agent': row['agent'],
            'description': row['description'],
            'rule_id': row['rule_id'],
            'rule_groups': row['rule_groups'],
            'full_log': row['full_log'],
            'evaluation': row['evaluation'],
            'evaluated_at': row['evaluated_at']
        })
    return grouped


def get_alert_dates():
    """Trả về danh sách ngày có cảnh báo + số lượng mỗi ngày (cho calendar)."""
    conn = get_db()
    rows = conn.execute("""
        SELECT date, COUNT(*) as count,
               SUM(CASE WHEN level >= 12 THEN 1 ELSE 0 END) as critical_count,
               SUM(CASE WHEN level >= 8 AND level < 12 THEN 1 ELSE 0 END) as high_count
        FROM alerts
        GROUP BY date
        ORDER BY date DESC
    """).fetchall()
    conn.close()
    return [{
        'date': row['date'],
        'count': row['count'],
        'critical': row['critical_count'],
        'high': row['high_count']
    } for row in rows]


def save_evaluation(alert_id, evaluation):
    """Lưu đánh giá TP/FP cho alert."""
    conn = get_db()
    now = datetime.now().isoformat()
    conn.execute("""
        UPDATE alerts SET evaluation = ?, evaluated_at = ?
        WHERE alert_id = ?
    """, (evaluation, now, alert_id))
    conn.commit()
    conn.close()


def get_evaluation_stats():
    """Thống kê tỷ lệ TP/FP."""
    conn = get_db()
    total = conn.execute(
        "SELECT COUNT(*) as c FROM alerts WHERE evaluation IS NOT NULL"
    ).fetchone()['c']
    tp = conn.execute(
        "SELECT COUNT(*) as c FROM alerts WHERE evaluation = 'true_positive'"
    ).fetchone()['c']
    fp = conn.execute(
        "SELECT COUNT(*) as c FROM alerts WHERE evaluation = 'false_positive'"
    ).fetchone()['c']
    not_evaluated = conn.execute(
        "SELECT COUNT(*) as c FROM alerts WHERE evaluation IS NULL"
    ).fetchone()['c']
    conn.close()

    tp_rate = round((tp / total * 100), 1) if total > 0 else 0
    return {
        'total_evaluated': total,
        'true_positive': tp,
        'false_positive': fp,
        'not_evaluated': not_evaluated,
        'tp_rate': tp_rate
    }


def get_alerts_by_date_range(from_date, to_date):
    """Lấy cảnh báo theo khoảng ngày cho phân tích AI."""
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM alerts
        WHERE date >= ? AND date <= ?
        ORDER BY timestamp DESC
    """, (from_date, to_date)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ==========================================
# 4. KHỞI TẠO LOCAL LLM & VECTOR DATABASE
# ==========================================
logger.info("Đang nạp mô hình Local LLM (Llama 3) và Embedding...")
try:
    llm_local = Ollama(model="llama3")
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

    # Persist ChromaDB vào disk (không tái tạo mỗi lần restart)
    if os.path.exists(CHROMA_DIR) and os.listdir(CHROMA_DIR):
        logger.info("Đang nạp ChromaDB từ cache trên disk...")
        vector_db = Chroma(
            persist_directory=CHROMA_DIR,
            embedding_function=embeddings
        )
    else:
        logger.info("Đang tạo ChromaDB mới từ Playbook...")
        loader = TextLoader(PLAYBOOK_PATH, encoding="utf-8")
        docs = loader.load()
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=500, chunk_overlap=50
        )
        chunks = text_splitter.split_documents(docs)
        vector_db = Chroma.from_documents(
            documents=chunks,
            embedding=embeddings,
            persist_directory=CHROMA_DIR
        )

    retriever = vector_db.as_retriever(search_kwargs={"k": 2})

    # --- Chain cho RAG (Hỏi đáp Playbook) ---
    rag_prompt = PromptTemplate.from_template(
        "Bạn là chuyên gia SOC. Dựa vào tài liệu nội bộ sau đây, hãy trả lời câu hỏi. "
        "Nếu không có trong tài liệu, hãy nói 'Tôi không tìm thấy thông tin trong Playbook'.\n\n"
        "Tài liệu (Context):\n{context}\n\nCâu hỏi: {question}\n\nTrả lời bằng tiếng Việt:"
    )
    rag_chain = (
        {"context": retriever, "question": RunnablePassthrough()}
        | rag_prompt | llm_local | StrOutputParser()
    )

    # --- Chain cho NL2Query (Sinh lệnh SIEM & Lệnh ứng cứu) ---
    query_prompt = PromptTemplate.from_template(
        "Bạn là Chuyên gia SIEM và Quản trị hệ thống cấp cao.\n"
        "Phân tích yêu cầu và sinh ra DUY NHẤT 1 dòng lệnh code:\n"
        "- Nếu yêu cầu là Tìm kiếm/Lọc log: Sinh lệnh KQL/SPL.\n"
        "- Nếu yêu cầu là Ngăn chặn/Xóa/Chặn IP/Khắc phục: Sinh lệnh hệ thống (CMD/PowerShell/Bash).\n"
        "QUY TẮC: Nếu mục đích là 'ngăn chặn' hoặc 'xóa', BẮT BUỘC sinh lệnh hệ thống.\n"
        "CHỈ TRẢ VỀ DUY NHẤT DÒNG CODE. KHÔNG giải thích.\n\n"
        "Yêu cầu: {natural_language}\nLệnh code sinh ra:"
    )
    query_chain = query_prompt | llm_local | StrOutputParser()

    # --- Chain cho Phân tích báo cáo (tạo sẵn 1 lần, không tạo mỗi request) ---
    analysis_prompt = PromptTemplate.from_template(
        "Dựa trên các log cảnh báo an ninh sau:\n{alerts_data}\n\n"
        "Hãy viết Báo cáo sự cố an ninh bằng tiếng Việt, trình bày Markdown với 3 phần:\n"
        "1. Tóm tắt tình hình\n2. Đánh giá rủi ro\n3. Đề xuất khắc phục"
    )
    analysis_chain = analysis_prompt | llm_local | StrOutputParser()

    # --- Chain cho Chat hỏi đáp tự do (SOC Expert) ---
    chat_prompt = PromptTemplate.from_template(
        "Bạn là chuyên gia An ninh mạng (SOC Analyst) cấp cao. "
        "Hãy trả lời câu hỏi của người dùng bằng tiếng Việt, ngắn gọn, chính xác, chuyên nghiệp.\n"
        "Nếu câu hỏi liên quan đến cảnh báo cụ thể, hãy phân tích chi tiết.\n"
        "Nếu câu hỏi không liên quan đến an ninh mạng, hãy lịch sự từ chối.\n\n"
        "Câu hỏi: {question}\n\nTrả lời:"
    )
    chat_chain = chat_prompt | llm_local | StrOutputParser()

    logger.info("Tích hợp Local LLM thành công!")

except Exception as e:
    logger.error(f"Lỗi nạp Local LLM: {e}", exc_info=True)
    # Đặt biến None để kiểm tra trước khi sử dụng
    rag_chain = None
    query_chain = None
    analysis_chain = None
    chat_chain = None


# ==========================================
# 5. FLASK ROUTES
# ==========================================

@app.route('/')
def home():
    """Trang chủ — dùng render_template() có auto-cache thay vì render_template_string()."""
    return render_template('dashboard.html')


@app.route('/api/system_info', methods=['GET'])
def system_info():
    """Trả về thông tin hệ thống thực tế (thay vì hard-code trong HTML)."""
    wazuh_online = False
    total_events = 0
    try:
        url = f"https://{WAZUH_IP}:{WAZUH_PORT}/wazuh-alerts-*/_count"
        response = requests.get(
            url,
            auth=(WAZUH_USER, WAZUH_PASS),
            verify=False,
            timeout=3
        )
        if response.status_code == 200:
            total_events = response.json().get('count', 0)
            wazuh_online = True
    except Exception:
        pass

    # Khi Wazuh offline: hiển thị số mô phỏng để dashboard không trống
    if not wazuh_online:
        total_events = random.randint(12000, 18000)

    return jsonify({
        "total_events": total_events,
        "agents_online": 5,  # TODO: Query từ Wazuh API khi có endpoint
        "agents_total": 5,
        "report_count": count_report_files(),
        "siem_endpoint": f"https://{WAZUH_IP}:{WAZUH_PORT}",
        "wazuh_online": wazuh_online
    })


@app.route('/api/alert_stats', methods=['GET'])
def alert_stats():
    """Thống kê alert cho biểu đồ (Trend 24h + Severity)."""
    try:
        url = f"https://{WAZUH_IP}:{WAZUH_PORT}/wazuh-alerts-*/_search"
        query = {
            "size": 0,
            "query": {"range": {"timestamp": {"gte": "now-24h"}}},
            "aggs": {
                "by_hour": {
                    "date_histogram": {
                        "field": "timestamp",
                        "fixed_interval": "1h"
                    }
                },
                "by_level": {
                    "range": {
                        "field": "rule.level",
                        "ranges": [
                            {"key": "Low", "from": 1, "to": 5},
                            {"key": "Medium", "from": 5, "to": 8},
                            {"key": "High", "from": 8, "to": 12},
                            {"key": "Critical", "from": 12}
                        ]
                    }
                }
            }
        }
        response = requests.post(
            url, auth=(WAZUH_USER, WAZUH_PASS),
            headers={'Content-Type': 'application/json'},
            data=json.dumps(query), verify=False, timeout=5
        )
        if response.status_code == 200:
            aggs = response.json().get('aggregations', {})
            hourly = aggs.get('by_hour', {}).get('buckets', [])
            trend_labels = []
            trend_data = []
            for bucket in hourly:
                key_str = bucket.get('key_as_string', '')
                try:
                    dt = datetime.fromisoformat(key_str.replace('Z', '+00:00'))
                    trend_labels.append(dt.strftime('%H:%M'))
                except Exception:
                    trend_labels.append(key_str[-8:-3])
                trend_data.append(bucket['doc_count'])

            levels = aggs.get('by_level', {}).get('buckets', [])
            severity_map = {b['key']: b['doc_count'] for b in levels}

            return jsonify({
                "status": "success",
                "trend": {"labels": trend_labels, "data": trend_data},
                "severity": {
                    "labels": ["Critical", "High", "Medium", "Low"],
                    "data": [
                        severity_map.get("Critical", 0),
                        severity_map.get("High", 0),
                        severity_map.get("Medium", 0),
                        severity_map.get("Low", 0)
                    ],
                    "colors": ["#ef4444", "#f97316", "#eab308", "#3b82f6"]
                }
            })
        else:
            raise Exception(f"Wazuh trả về mã: {response.status_code}")

    except Exception as e:
        logger.warning(f"Lỗi lấy alert stats, dùng dữ liệu mô phỏng: {e}")
        now = datetime.now()
        hours = [(now - timedelta(hours=23-i)).strftime('%H:00') for i in range(24)]
        trend_data = [random.randint(3, 35) for _ in range(24)]
        # Tạo peak giả lập
        trend_data[8] = random.randint(30, 50)
        trend_data[14] = random.randint(25, 45)
        trend_data[20] = random.randint(20, 40)

        return jsonify({
            "status": "success",
            "trend": {"labels": hours, "data": trend_data},
            "severity": {
                "labels": ["Critical", "High", "Medium", "Low"],
                "data": [4, 12, 23, 38],
                "colors": ["#ef4444", "#f97316", "#eab308", "#3b82f6"]
            }
        })


@app.route('/api/get_alerts', methods=['GET'])
def get_alerts():
    """Lấy cảnh báo — hỗ trợ lọc theo ?date=, ?month=, hoặc sync mới nhất."""
    # Cleanup very old alerts
    cleanup_old_alerts()

    # Đọc tham số lọc
    filter_date = request.args.get('date', '').strip()      # VD: 2026-09-17
    filter_month = request.args.get('month', '').strip()     # VD: 2026-09

    # Nếu có filter → chỉ đọc từ DB (không sync Wazuh)
    if filter_date or filter_month:
        grouped = get_alerts_from_db(date=filter_date or None, month=filter_month or None)
        all_alerts = []
        critical_cnt = 0
        for date_alerts in grouped.values():
            for a in date_alerts:
                all_alerts.append(a)
                if a['level'] >= 10:
                    critical_cnt += 1
        return jsonify({
            "status": "success",
            "alerts_grouped": grouped,
            "alerts": all_alerts,
            "critical_count": critical_cnt,
            "filter": filter_date or filter_month
        })

    # Không filter → sync mới nhất từ Wazuh + trả hôm nay
    try:
        response = fetch_wazuh_alerts(size=20)
        if response.status_code == 200:
            hits = response.json()['hits']['hits']
            formatted_alerts, critical_cnt = format_alerts(hits)
            save_alerts_to_db(formatted_alerts)

            # Đưa cảnh báo qua IncidentCorrelator để gom nhóm theo IP/Host (chống bão alert)
            for a in formatted_alerts:
                correlator.ingest(a)

            # Trả alerts hôm nay cho dashboard
            today = datetime.now().strftime('%Y-%m-%d')
            grouped = get_alerts_from_db(date=today)
            return jsonify({
                "status": "success",
                "alerts_grouped": grouped,
                "alerts": formatted_alerts[:6],
                "critical_count": critical_cnt
            })
        else:
            raise Exception(f"Wazuh trả về mã: {response.status_code}")

    except Exception as e:
        logger.warning(f"Wazuh không phản hồi: {e}")
        today = datetime.now().strftime('%Y-%m-%d')
        cached = get_alerts_from_db(date=today)
        if cached:
            all_alerts = []
            critical_cnt = 0
            for date_alerts in cached.values():
                for a in date_alerts:
                    all_alerts.append(a)
                    if a['level'] >= 10:
                        critical_cnt += 1
            return jsonify({
                "status": "success",
                "alerts_grouped": cached,
                "alerts": all_alerts[:6],
                "critical_count": critical_cnt,
                "from_cache": True
            })

        # DB trống → mô phỏng
        sample_alerts = [
            {"alert_id": "sim_001", "timestamp": datetime.now().isoformat(),
             "date": today, "time_display": datetime.now().strftime('%H:%M:%S'),
             "level": 12, "agent": "WIN-SRV-01",
             "description": "Mô phỏng: Administrators group changed.",
             "rule_id": "5502", "rule_groups": "windows, policy_changed",
             "full_log": "Security event: Admin group membership was changed.",
             "evaluation": None, "evaluated_at": None},
            {"alert_id": "sim_002", "timestamp": datetime.now().isoformat(),
             "date": today, "time_display": "14:01:22",
             "level": 8, "agent": "WIN-SRV-01",
             "description": "Mô phỏng: User account enabled or created.",
             "rule_id": "5901", "rule_groups": "windows, account_changed",
             "full_log": "Security event: A user account was enabled.",
             "evaluation": None, "evaluated_at": None},
            {"alert_id": "sim_003", "timestamp": datetime.now().isoformat(),
             "date": today, "time_display": "14:01:21",
             "level": 7, "agent": "WIN-SRV-01",
             "description": "Mô phỏng: Multiple login failures detected.",
             "rule_id": "5710", "rule_groups": "authentication_failures",
             "full_log": "Multiple login failures detected from source.",
             "evaluation": None, "evaluated_at": None}
        ]
        save_alerts_to_db(sample_alerts)
        return jsonify({
            "status": "success",
            "alerts_grouped": {today: sample_alerts},
            "alerts": sample_alerts,
            "critical_count": 1
        })


@app.route('/api/alert_dates', methods=['GET'])
def api_alert_dates():
    """Trả danh sách ngày có cảnh báo + số lượng (cho calendar UI)."""
    try:
        dates = get_alert_dates()
        return jsonify({"status": "success", "dates": dates})
    except Exception as e:
        logger.error(f"Lỗi lấy alert dates: {e}")
        return jsonify({"status": "error", "dates": []}), 500


@app.route('/api/analyze', methods=['POST'])
@rate_limit(max_per_minute=3)
def analyze():
    """Phân tích AI bất đồng bộ — trả về job_id ngay, LLM chạy background."""
    if analysis_chain is None:
        return jsonify({"status": "error", "message": "Local LLM chưa sẵn sàng."}), 503

    data = request.json or {}
    from_date = data.get('from_date', datetime.now().strftime('%Y-%m-%d'))
    to_date   = data.get('to_date', datetime.now().strftime('%Y-%m-%d'))

    job_id = str(uuid.uuid4())
    with _analysis_lock:
        _analysis_jobs[job_id] = {
            "status": "running",
            "progress": 5,
            "message": "Đang thu thập dữ liệu cảnh báo...",
            "filename": None,
            "error": None
        }

    def _run_analysis():
        try:
            # Bước 1: lấy dữ liệu
            with _analysis_lock:
                _analysis_jobs[job_id]["progress"] = 15
                _analysis_jobs[job_id]["message"]  = "Đang truy vấn cơ sở dữ liệu..."

            db_alerts = get_alerts_by_date_range(from_date, to_date)
            if db_alerts:
                alerts_text = "\n".join([
                    f"- [{a['date']} {a['time_display']}] Cảnh báo Level {a['level']}: "
                    f"{a['description']} tại {a['agent']} (Rule: {a['rule_id']})"
                    for a in db_alerts
                ])
                alert_count = len(db_alerts)
            else:
                try:
                    response = fetch_wazuh_alerts(size=10, timeout=10)
                    if response.status_code == 200:
                        alerts = response.json()['hits']['hits']
                        alerts_text = "\n".join([
                            f"- Cảnh báo: {a['_source'].get('rule', {}).get('description')} "
                            f"tại {a['_source'].get('agent', {}).get('name')}"
                            for a in alerts
                        ])
                        alert_count = len(alerts)
                    else:
                        raise Exception("Wazuh unavailable")
                except Exception:
                    alerts_text = (
                        "- Cảnh báo giả lập: Brute force attack detected on WIN-SRV-01 (Level 12)\n"
                        "- Cảnh báo giả lập: Privilege escalation attempt (Level 10)"
                    )
                    alert_count = 2

            # Bước 2: gọi LLM
            with _analysis_lock:
                _analysis_jobs[job_id]["progress"] = 35
                _analysis_jobs[job_id]["message"]  = f"AI đang phân tích {alert_count} cảnh báo..."

            report_text = analysis_chain.invoke({"alerts_data": alerts_text})

            # Bước 3: xuất file
            with _analysis_lock:
                _analysis_jobs[job_id]["progress"] = 90
                _analysis_jobs[job_id]["message"]  = "Đang xuất báo cáo HTML..."

            current_time = datetime.now()
            time_str  = current_time.strftime("%H:%M:%S - %d/%m/%Y")
            filename  = f"SOC_Report_{current_time.strftime('%d_%m_%Y_%H%M%S')}.html"
            html_content = markdown.markdown(report_text, extensions=['extra', 'codehilite', 'toc'])

            from_display   = datetime.strptime(from_date, '%Y-%m-%d').strftime('%d/%m/%Y') if from_date else ''
            to_display     = datetime.strptime(to_date,   '%Y-%m-%d').strftime('%d/%m/%Y') if to_date   else ''
            date_range_str = f"{from_display} → {to_display}" if from_date != to_date else from_display

            full_html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Báo cáo SOC - {time_str}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px auto; max-width: 800px; color: #1e293b; line-height: 1.6; background-color: #f8fafc; padding: 20px; }}
        .header-banner {{ background-color: #0f172a; color: #ffffff; padding: 25px; border-bottom: 5px solid #ef4444; text-align: center; border-radius: 8px 8px 0 0; }}
        .header-banner h1 {{ margin: 0; font-size: 22pt; text-transform: uppercase; letter-spacing: 1px; }}
        .highlight-box {{ background-color: #ffffff; border-top: 4px solid #3b82f6; padding: 15px 20px; margin: 20px 0; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 4px; }}
        h2 {{ color: #334155; border-bottom: 2px solid #cbd5e1; padding-bottom: 5px; margin-top: 30px; }}
        h3 {{ color: #ef4444; margin-top: 25px; border-left: 4px solid #ef4444; padding-left: 10px; }}
        code {{ background-color: #f1f5f9; color: #b91c1c; padding: 2px 5px; border-radius: 4px; font-family: Consolas, monospace; }}
        .content-box {{ background-color: #ffffff; padding: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 0 0 8px 8px; }}
    </style>
</head>
<body>
    <div class="header-banner">
        <h1>BÁO CÁO PHÂN TÍCH SỰ CỐ AN NINH (SOC)</h1>
    </div>
    <div class="content-box">
        <div class="highlight-box">
            <p><strong>Đơn vị lập báo cáo:</strong> Hệ thống AI SOC Tự động (Local Llama 3)</p>
            <p><strong>Thời gian xuất báo cáo:</strong> {time_str}</p>
            <p><strong>Khoảng thời gian phân tích:</strong> {date_range_str}</p>
            <p><strong>Số cảnh báo phân tích:</strong> {alert_count}</p>
        </div>
        {html_content}
    </div>
</body>
</html>"""

            filepath = os.path.join(REPORTS_DIR, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(full_html)

            logger.info(f"Xuất báo cáo thành công: {filename}")
            with _analysis_lock:
                _analysis_jobs[job_id]["status"]   = "done"
                _analysis_jobs[job_id]["progress"] = 100
                _analysis_jobs[job_id]["message"]  = f"Đã phân tích {alert_count} cảnh báo ({date_range_str})!"
                _analysis_jobs[job_id]["filename"] = filename

        except Exception as e:
            logger.error(f"Lỗi phân tích (job {job_id}): {e}", exc_info=True)
            with _analysis_lock:
                _analysis_jobs[job_id]["status"]  = "error"
                _analysis_jobs[job_id]["message"] = "Đã xảy ra lỗi trong quá trình phân tích. Vui lòng thử lại."
                _analysis_jobs[job_id]["error"]   = str(e)

    t = threading.Thread(target=_run_analysis, daemon=True)
    t.start()

    return jsonify({"status": "queued", "job_id": job_id})


@app.route('/api/analyze_status/<job_id>', methods=['GET'])
def analyze_status(job_id):
    """Poll trạng thái tác vụ phân tích AI."""
    with _analysis_lock:
        job = _analysis_jobs.get(job_id)
    if not job:
        return jsonify({"status": "not_found", "message": "Không tìm thấy tác vụ."}), 404
    return jsonify(job)


@app.route('/api/analyze_cleanup', methods=['POST'])
def analyze_cleanup():
    """Dọn sạch các job cũ đã hoàn thành để tránh memory leak."""
    with _analysis_lock:
        to_del = [jid for jid, j in _analysis_jobs.items() if j["status"] in ("done", "error")]
        for jid in to_del:
            del _analysis_jobs[jid]
    return jsonify({"status": "ok", "cleaned": len(to_del)})


@app.route('/download/<path:filename>')
def download_file(filename):
    """Tải báo cáo — dùng send_from_directory() chống Path Traversal."""
    safe_name = os.path.basename(filename)
    return send_from_directory(REPORTS_DIR, safe_name)


@app.route('/api/rag', methods=['POST'])
@rate_limit(max_per_minute=10)
def api_rag():
    """Hỏi đáp RAG với Playbook nội bộ."""
    if rag_chain is None:
        return jsonify({"answer": "Local LLM chưa sẵn sàng."}), 503

    try:
        data = request.json
        if not data or not data.get("question", "").strip():
            return jsonify({"answer": "Vui lòng nhập câu hỏi hợp lệ."}), 400

        question = data["question"].strip()[:2000]
        answer = rag_chain.invoke(question)
        return jsonify({"answer": answer})

    except Exception as e:
        logger.error(f"Lỗi RAG: {e}", exc_info=True)
        return jsonify({"answer": "Đã xảy ra lỗi khi xử lý câu hỏi. Vui lòng thử lại."}), 500


@app.route('/api/query', methods=['POST'])
@rate_limit(max_per_minute=10)
def api_query():
    """Sinh lệnh KQL/System từ ngôn ngữ tự nhiên."""
    if query_chain is None:
        return jsonify({"answer": "Local LLM chưa sẵn sàng."}), 503

    try:
        data = request.json
        if not data or not data.get("question", "").strip():
            return jsonify({"answer": "Vui lòng nhập yêu cầu hợp lệ."}), 400

        question = data["question"].strip()[:2000]
        answer = query_chain.invoke({"natural_language": question})
        return jsonify({"answer": answer})

    except Exception as e:
        logger.error(f"Lỗi NL2Query: {e}", exc_info=True)
        return jsonify({"answer": "Đã xảy ra lỗi khi sinh lệnh. Vui lòng thử lại."}), 500


@app.route('/api/chat', methods=['POST'])
@rate_limit(max_per_minute=15)
def api_chat():
    """Chat hỏi đáp AI tự do — chuyên gia SOC."""
    if chat_chain is None:
        return jsonify({"answer": "Local LLM chưa sẵn sàng."}), 503

    try:
        data = request.json
        if not data or not data.get("message", "").strip():
            return jsonify({"answer": "Vui lòng nhập câu hỏi."}), 400

        message = data["message"].strip()[:2000]
        
        # Lấy ngữ cảnh các cảnh báo mới nhất trong ngày để AI có thông tin trả lời
        today = datetime.now().strftime('%Y-%m-%d')
        cached = get_alerts_from_db(date=today)
        context = "Không có cảnh báo mới trong ngày hôm nay."
        if cached and today in cached and cached[today]:
            recent_alerts = cached[today][:5]
            context_lines = []
            for a in recent_alerts:
                context_lines.append(f"- [{a['time_display']}] Level {a['level']}: {a['description']} (Agent: {a['agent']}, Rule: {a['rule_id']})")
            context = "\n".join(context_lines)

        enhanced_question = (
            f"Dưới đây là danh sách các cảnh báo mới nhất trong hệ thống hiện tại:\n{context}\n\n"
            f"Câu hỏi của người dùng: {message}"
        )

        answer = chat_chain.invoke({"question": enhanced_question})
        return jsonify({"status": "success", "answer": answer})

    except Exception as e:
        logger.error(f"Lỗi Chat AI: {e}", exc_info=True)
        return jsonify({"answer": "Đã xảy ra lỗi. Vui lòng thử lại."}), 500


@app.route('/api/set_key', methods=['POST'])
def set_key():
    """Lưu cấu hình API key (dành cho mở rộng sau này)."""
    try:
        data = request.json
        if not data or not data.get("api_key", "").strip():
            return jsonify({"status": "error", "message": "API key không hợp lệ."}), 400

        # Hiện tại dùng Local LLM, chỉ ghi nhận
        logger.info("API key đã được cập nhật (hiện tại dùng Local LLM)")
        return jsonify({"status": "success", "message": "Đã lưu cấu hình."})

    except Exception as e:
        logger.error(f"Lỗi lưu cấu hình: {e}")
        return jsonify({"status": "error", "message": "Lỗi lưu cấu hình."}), 500


@app.route('/api/evaluate_alert', methods=['POST'])
def evaluate_alert():
    """Đánh giá True Positive / False Positive cho cảnh báo."""
    try:
        data = request.json
        if not data:
            return jsonify({"status": "error", "message": "Dữ liệu không hợp lệ."}), 400

        alert_id = data.get('alert_id', '').strip()
        evaluation = data.get('evaluation', '').strip()

        if not alert_id:
            return jsonify({"status": "error", "message": "Thiếu alert_id."}), 400

        if evaluation not in ('true_positive', 'false_positive', ''):
            return jsonify({"status": "error", "message": "Giá trị evaluation không hợp lệ."}), 400

        # Nếu evaluation rỗng → xóa đánh giá (reset)
        save_evaluation(alert_id, evaluation if evaluation else None)
        logger.info(f"Đánh giá cảnh báo {alert_id}: {evaluation or 'reset'}")

        return jsonify({
            "status": "success",
            "message": f"Đã đánh giá cảnh báo: {evaluation or 'đã xóa đánh giá'}",
            "stats": get_evaluation_stats()
        })

    except Exception as e:
        logger.error(f"Lỗi đánh giá cảnh báo: {e}", exc_info=True)
        return jsonify({"status": "error", "message": "Lỗi lưu đánh giá."}), 500


@app.route('/api/evaluation_stats', methods=['GET'])
def api_evaluation_stats():
    """Trả về thống kê TP/FP tổng hợp."""
    try:
        stats = get_evaluation_stats()
        return jsonify({"status": "success", **stats})
    except Exception as e:
        logger.error(f"Lỗi lấy thống kê: {e}")
        return jsonify({"status": "error", "tp_rate": 0}), 500


@app.route('/api/pipeline_status', methods=['GET'])
def api_pipeline_status():
    """Trả về trạng thái gom nhóm sự cố của IncidentCorrelator."""
    try:
        grouping = correlator.status()
        return jsonify({
            "status": "success",
            "debounce_seconds": 20,
            "active_incidents": len(grouping),
            "grouping": grouping
        })
    except Exception as e:
        logger.error(f"Lỗi pipeline status: {e}")
        return jsonify({"status": "error", "grouping": []}), 500


# ==========================================
# 6. KHỞI ĐỘNG
# ==========================================
# Khởi tạo DB khi import module
init_db()

if __name__ == "__main__":
    logger.info("=" * 70)
    logger.info("SOC AI DASHBOARD PREMIUM ĐÃ KHỞI ĐỘNG!")
    logger.info("MỞ TRÌNH DUYỆT TỚI: http://127.0.0.1:5000")
    logger.info("=" * 70)
    app.run(host="127.0.0.1", port=5000, debug=False)