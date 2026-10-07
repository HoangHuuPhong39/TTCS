import requests
import json
import urllib3
import os
import markdown
from datetime import datetime
from flask import Flask, jsonify, render_template_string
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# 1. CẤU HÌNH HỆ THỐNG WAZUH & GEMINI
# ==========================================
WAZUH_IP = os.getenv("WAZUH_IP", "192.168.1.100")
PORT = int(os.getenv("WAZUH_PORT", "9200"))
USERNAME = os.getenv("WAZUH_USER", "admin")
PASSWORD = os.getenv("WAZUH_PASS", "password")
# Lay API key tu bien moi truong
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
os.environ["GOOGLE_API_KEY"] = GOOGLE_API_KEY

url = f"https://{WAZUH_IP}:{PORT}/wazuh-alerts-*/_search"

query = {
    "size": 5,
    "sort": [{"timestamp": {"order": "desc"}}],
    "query": {"range": {"rule.level": {"gte": 7}}}
}
headers = {'Content-Type': 'application/json'}

app = Flask(__name__)

# ==========================================
# 2. GIAO DIỆN WEB (HTML/CSS/JS)
# ==========================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KMA Cloud SOC - Gemini Integration</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #0f172a; color: #e2e8f0; }
        .glass-panel { background: rgba(30, 41, 59, 0.8); backdrop-filter: blur(12px); border: 1px solid #334155; }
        .markdown-body h2 { color: #38bdf8; font-size: 1.5rem; font-weight: bold; margin-top: 1.5rem; margin-bottom: 0.5rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }
        .markdown-body h3 { color: #f87171; font-size: 1.25rem; font-weight: bold; margin-top: 1rem; margin-bottom: 0.5rem; }
        .markdown-body ul { list-style-type: disc; padding-left: 1.5rem; margin-bottom: 1rem; }
        .markdown-body p { margin-bottom: 1rem; }
        .markdown-body strong { color: #e2e8f0; }
        .loading-spinner { border: 3px solid rgba(255,255,255,0.1); border-radius: 50%; border-top: 3px solid #38bdf8; width: 20px; height: 20px; animation: spin 1s linear infinite; display: none; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body class="min-h-screen p-6 flex flex-col">
    
    <!-- Header -->
    <header class="flex items-center justify-between mb-8 pb-4 border-b border-slate-700">
        <div class="flex items-center gap-4">
            <div class="p-3 bg-sky-600 rounded-lg shadow-lg shadow-sky-500/30">
                <i class="fa-solid fa-cloud-bolt text-2xl text-white"></i>
            </div>
            <div>
                <h1 class="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-sky-400 to-blue-500">CLOUD SOC DASHBOARD</h1>
                <p class="text-slate-400 text-sm">Tích hợp Wazuh & Google Gemini AI</p>
            </div>
        </div>
        <div class="flex gap-3">
            <button onclick="analyzeLogs()" id="btn-analyze" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-6 rounded-lg transition-all flex items-center gap-2 shadow-lg shadow-blue-500/30">
                <i class="fa-solid fa-microchip"></i> Thu thập Log & Phân tích
                <div id="spinner" class="loading-spinner"></div>
            </button>
        </div>
    </header>

    <!-- Main Content -->
    <div class="flex-grow grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Panel Trái: Thông tin hệ thống -->
        <div class="glass-panel rounded-xl p-6 h-fit">
            <h2 class="text-lg font-bold mb-4 text-slate-200 border-b border-slate-700 pb-2"><i class="fa-solid fa-server mr-2"></i> Trạng thái Hệ thống</h2>
            <div class="space-y-4 text-sm">
                <div class="flex justify-between items-center bg-slate-800/50 p-3 rounded border border-slate-700">
                    <span class="text-slate-400">SIEM Node:</span>
                    <span class="font-mono text-emerald-400">192.168.157.128:9200</span>
                </div>
                <div class="flex justify-between items-center bg-slate-800/50 p-3 rounded border border-slate-700">
                    <span class="text-slate-400">Mức độ cảnh báo:</span>
                    <span class="font-mono text-amber-400">Level &ge; 7</span>
                </div>
                <div class="flex justify-between items-center bg-slate-800/50 p-3 rounded border border-slate-700">
                    <span class="text-slate-400">AI Model:</span>
                    <span class="font-mono text-sky-400">Gemini 3.5 Flash</span>
                </div>
            </div>
            <div id="status-message" class="mt-6 text-sm text-slate-400 italic">
                Hệ thống đang chờ lệnh...
            </div>
        </div>

        <!-- Panel Phải: Báo cáo AI -->
        <div class="glass-panel rounded-xl p-6 lg:col-span-2 flex flex-col shadow-2xl">
            <h2 class="text-lg font-bold mb-4 text-slate-200 flex items-center justify-between border-b border-slate-700 pb-2">
                <span><i class="fa-solid fa-file-contract mr-2"></i> Báo Cáo Phân Tích Sự Cố</span>
                <span id="report-time" class="text-sm font-normal text-slate-400"></span>
            </h2>
            <div id="report-content" class="markdown-body flex-grow bg-slate-900/50 rounded-lg p-6 border border-slate-700 overflow-y-auto" style="max-height: 600px;">
                <div class="h-full flex flex-col items-center justify-center text-slate-500 space-y-4">
                    <i class="fa-solid fa-shield-halved text-6xl opacity-20"></i>
                    <p>Nhấn "Thu thập Log & Phân tích" để AI bắt đầu quét hệ thống Wazuh.</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        async function analyzeLogs() {
            const btn = document.getElementById('btn-analyze');
            const spinner = document.getElementById('spinner');
            const content = document.getElementById('report-content');
            const statusMsg = document.getElementById('status-message');
            const timeSpan = document.getElementById('report-time');

            // Hiệu ứng đang xử lý
            btn.disabled = true;
            spinner.style.display = 'block';
            content.innerHTML = '<div class="flex flex-col items-center justify-center h-full text-blue-400 space-y-4"><i class="fa-solid fa-satellite-dish text-4xl animate-bounce"></i><p>Đang kéo log từ Wazuh và gửi sang Google Gemini...</p></div>';
            statusMsg.innerHTML = '<span class="text-blue-400"><i class="fa-solid fa-circle-notch fa-spin mr-1"></i> Đang xử lý dữ liệu...</span>';

            try {
                const response = await fetch('/api/run_analysis', { method: 'POST' });
                const data = await response.json();

                if (response.ok) {
                    content.innerHTML = data.html_report;
                    timeSpan.innerText = "Cập nhật lúc: " + new Date().toLocaleTimeString('vi-VN');
                    statusMsg.innerHTML = `<span class="text-emerald-400"><i class="fa-solid fa-check mr-1"></i> ${data.message}</span><br><span class="text-xs text-slate-500">Đã lưu file: ${data.saved_file}</span>`;
                } else {
                    content.innerHTML = `<div class="text-red-400 font-bold p-4"><i class="fa-solid fa-triangle-exclamation mr-2"></i> Lỗi: ${data.error}</div>`;
                    statusMsg.innerHTML = '<span class="text-red-400"><i class="fa-solid fa-xmark mr-1"></i> Phân tích thất bại.</span>';
                }
            } catch (error) {
                content.innerHTML = `<div class="text-red-400 font-bold p-4">Lỗi kết nối: ${error.message}</div>`;
            }

            // Khôi phục nút
            btn.disabled = false;
            spinner.style.display = 'none';
        }
    </script>
</body>
</html>
"""

# ==========================================
# 3. LOGIC XỬ LÝ BACKEND
# ==========================================
def process_wazuh_logs():
    """Hàm lõi kế thừa từ script cũ để lấy log và gọi AI"""
    current_time = datetime.now()
    date_str = current_time.strftime("%d_%m_%Y")
    time_str = current_time.strftime("%H:%M:%S - %d/%m/%Y")
    
    # 1. Kéo log từ Wazuh
    response = requests.post(url, auth=(USERNAME, PASSWORD), headers=headers, data=json.dumps(query), verify=False)
    
    if response.status_code != 200:
        raise Exception(f"Không thể kết nối Wazuh. Mã lỗi: {response.status_code}")
        
    alerts = response.json()['hits']['hits']
    if not alerts:
        raise Exception("Không tìm thấy cảnh báo nào có Level >= 7 trong hệ thống.")
        
    alerts_text = "".join([f"- Cảnh báo: {a['_source'].get('rule', {}).get('description')} tại {a['_source'].get('agent', {}).get('name')}\n" for a in alerts])
    
    # 2. Gọi Google Gemini
    llm = ChatGoogleGenerativeAI(model="models/gemini-3.5-flash", temperature=0.2)
    template = "Dựa trên các log: {alerts_data}. Hãy viết Báo cáo sự cố an ninh bằng tiếng Việt, trình bày Markdown với 3 phần: 1. Tóm tắt, 2. Đánh giá rủi ro, 3. Đề xuất khắc phục."
    prompt = PromptTemplate(input_variables=["alerts_data"], template=template)
    
    report = (prompt | llm).invoke({"alerts_data": alerts_text})
    report_text = report.content[0]['text'] if isinstance(report.content, list) else report.content
    
    # 3. Xử lý định dạng HTML để trả về Frontend và lưu file
    html_content = markdown.markdown(report_text)
    
    # Lưu ra file Báo cáo giao diện đẹp như script cũ
    full_html = f"""
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
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
                <p><strong>Đơn vị lập báo cáo:</strong> Hệ thống AI SOC Tự động (Gemini)</p>
                <p><strong>Thời gian xuất báo cáo:</strong> {time_str}</p>
            </div>
            {html_content.replace('<h3>', '<h2>').replace('</h3>', '</h2>').replace('####', '<h3>')}
        </div>
    </body>
    </html>
    """
    filename = f"SOC_Report_{date_str}.html"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(full_html)
        
    return html_content, filename

# ==========================================
# 4. ĐỊNH TUYẾN WEB (ROUTES)
# ==========================================
@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/run_analysis', methods=['POST'])
def run_analysis():
    try:
        html_report, saved_file = process_wazuh_logs()
        return jsonify({
            "status": "success",
            "message": "Phân tích AI hoàn tất!",
            "html_report": html_report,
            "saved_file": saved_file
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

if __name__ == "__main__":
    print("\n" + "="*70)
    print("🚀 CLOUD SOC DASHBOARD ĐÃ SẴN SÀNG!")
    print("👉 HÃY MỞ TRÌNH DUYỆT VÀ TRUY CẬP: http://127.0.0.1:5001")
    print("="*70 + "\n")
    # Chạy trên port 5001 để không bị trùng với ứng dụng Local LLM lúc trước
    app.run(host="127.0.0.1", port=5001, debug=False)