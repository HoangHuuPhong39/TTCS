"""
vulns_blueprint.py - Module Quản lý & Khắc phục Lỗ hổng (CVE) cho Flask SOC Dashboard
Tương thích với Wazuh Vulnerability Detection (chỉ mục wazuh-states-vulnerabilities-*)
Hỗ trợ sinh Kế hoạch khắc phục (Remediation Plan) tự động qua Local LLM.
"""

import os
import json
import logging
import requests
import urllib3
from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

vulns_bp = Blueprint('vulns', __name__)

WAZUH_IP = os.getenv("WAZUH_IP", "192.168.157.128")
WAZUH_PORT = int(os.getenv("WAZUH_PORT", "9200"))
WAZUH_USER = os.getenv("WAZUH_USER", "admin")
WAZUH_PASS = os.getenv("WAZUH_PASS", "")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
MODEL_NAME = os.getenv("OLLAMA_MODEL", "llama3")

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
DEFAULT_PRIORITY = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}

# Dữ liệu mô phỏng chuẩn CVE thực tế khi Wazuh Indexer offline hoặc chưa kích hoạt vulnerability detector
MOCK_CVES = [
    {
        "cve_id": "CVE-2021-44228",
        "severity": "Critical",
        "cvss": 10.0,
        "package_name": "log4j-core",
        "package_version": "2.14.1",
        "title": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "affected_agents": ["WEB-SRV-01", "APP-PROD-02"],
        "status": "Active",
        "priority": "P1",
        "published": "2021-12-10"
    },
    {
        "cve_id": "CVE-2024-21413",
        "severity": "Critical",
        "cvss": 9.8,
        "package_name": "Microsoft Outlook",
        "package_version": "16.0.17126.20132",
        "title": "Microsoft Outlook Remote Code Execution Vulnerability (MonikerLink)",
        "affected_agents": ["WIN-SRV-01", "CEO-LAPTOP"],
        "status": "Active",
        "priority": "P1",
        "published": "2024-02-13"
    },
    {
        "cve_id": "CVE-2022-22965",
        "severity": "Critical",
        "cvss": 9.8,
        "package_name": "spring-beans",
        "package_version": "5.3.17",
        "title": "Spring Framework RCE via Data Binding on JDK 9+ (Spring4Shell)",
        "affected_agents": ["APP-PROD-02"],
        "status": "Active",
        "priority": "P1",
        "published": "2022-03-31"
    },
    {
        "cve_id": "CVE-2023-38606",
        "severity": "High",
        "cvss": 7.8,
        "package_name": "kernel-headers",
        "package_version": "5.15.0-76",
        "title": "Local Privilege Escalation via memory manipulation",
        "affected_agents": ["LINUX-DB-01"],
        "status": "Active",
        "priority": "P2",
        "published": "2023-07-24"
    },
    {
        "cve_id": "CVE-2024-3094",
        "severity": "Critical",
        "cvss": 10.0,
        "package_name": "xz-utils",
        "package_version": "5.6.0",
        "title": "Backdoor in upstream xz/liblzma leading to SSH compromise",
        "affected_agents": ["LINUX-GW-01"],
        "status": "Mitigated",
        "priority": "P1",
        "published": "2024-03-29"
    },
    {
        "cve_id": "CVE-2023-4863",
        "severity": "High",
        "cvss": 8.8,
        "package_name": "libwebp",
        "package_version": "1.2.4",
        "title": "Heap buffer overflow in libwebp in WebP Codec",
        "affected_agents": ["WIN-SRV-01", "WEB-SRV-01"],
        "status": "Active",
        "priority": "P2",
        "published": "2023-09-12"
    }
]


@vulns_bp.route('/api/v1/soc/vulns', methods=['GET'])
def get_vulnerabilities():
    """Lấy danh sách các lỗ hổng bảo mật CVE từ Wazuh Indexer hoặc Fallback Mock."""
    severity_filter = request.args.get('severity', '').capitalize()
    search = request.args.get('search', '').strip().lower()

    cvss_min = request.args.get('cvss_min', type=float)

    # 1. Thử truy vấn Elasticsearch / OpenSearch của Wazuh
    url = f"https://{WAZUH_IP}:{WAZUH_PORT}/wazuh-states-vulnerabilities-*/_search"
    query = {
        "size": 50,
        "sort": [{"vulnerability.severity": {"order": "desc"}}],
        "query": {"match_all": {}}
    }

    try:
        resp = requests.post(
            url,
            auth=(WAZUH_USER, WAZUH_PASS),
            headers={'Content-Type': 'application/json'},
            data=json.dumps(query),
            verify=False,
            timeout=3
        )
        if resp.status_code == 200:
            hits = resp.json().get('hits', {}).get('hits', [])
            cve_map = {}
            for h in hits:
                s = h.get('_source', {})
                v = s.get('vulnerability', {})
                cve_id = v.get('id', '')
                if not cve_id:
                    continue

                sev = (v.get('severity') or 'Medium').capitalize()
                cvss_val = float(v.get('cvss', {}).get('cvss3', {}).get('base_score') or v.get('score', 0.0) or 5.0)
                pkg = s.get('package', {}).get('name', 'N/A')
                pkg_ver = s.get('package', {}).get('version', '')
                agent = s.get('agent', {}).get('name', 'Unknown')

                if cve_id not in cve_map:
                    cve_map[cve_id] = {
                        "cve_id": cve_id,
                        "severity": sev,
                        "cvss": cvss_val,
                        "package_name": pkg,
                        "package_version": pkg_ver,
                        "title": v.get('title') or v.get('description', '')[:120],
                        "affected_agents": [agent],
                        "status": "Active",
                        "priority": DEFAULT_PRIORITY.get(sev, "P3"),
                        "published": v.get('published', '')[:10]
                    }
                else:
                    if agent not in cve_map[cve_id]["affected_agents"]:
                        cve_map[cve_id]["affected_agents"].append(agent)
            
            cve_list = list(cve_map.values())
        else:
            cve_list = list(MOCK_CVES)
    except Exception as e:
        logger.warning(f"Không thể kết nối Wazuh CVE indexer ({e}), sử dụng bộ dữ liệu mô phỏng tiêu chuẩn.")
        cve_list = list(MOCK_CVES)

    # 2. Áp dụng bộ lọc
    if severity_filter and severity_filter in SEVERITY_ORDER:
        cve_list = [c for c in cve_list if c["severity"].lower() == severity_filter.lower()]

    if cvss_min is not None:
        cve_list = [c for c in cve_list if c["cvss"] >= cvss_min]

    if search:
        cve_list = [c for c in cve_list if search in c["cve_id"].lower() or search in c["package_name"].lower() or search in c["title"].lower()]

    # Sắp xếp theo CVSS giảm dần
    cve_list.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 9), -x["cvss"]))

    stats = {
        "total": len(cve_list),
        "critical": sum(1 for c in cve_list if c["severity"] == "Critical"),
        "high": sum(1 for c in cve_list if c["severity"] == "High"),
        "medium": sum(1 for c in cve_list if c["severity"] == "Medium"),
        "low": sum(1 for c in cve_list if c["severity"] == "Low")
    }

    return jsonify({
        "status": "success",
        "stats": stats,
        "vulnerabilities": cve_list
    })


@vulns_bp.route('/api/v1/soc/cve/remediation', methods=['POST'])
def generate_cve_remediation():
    """Gọi Local LLM sinh kế hoạch khắc phục ngắn gọn, chuẩn cấu trúc cho 1 CVE."""
    data = request.json or {}
    cve_id = data.get("cve_id", "CVE-Unknown")
    severity = data.get("severity", "High")
    cvss = data.get("cvss", 7.5)
    package = data.get("package", "Unknown Package")
    title = data.get("title", "")

    prompt = f"""Bạn là Chuyên gia An toàn thông tin Blue-team cấp cao.
Thông tin lỗ hổng bảo mật:
- Mã CVE: {cve_id}
- Mức độ: {severity} (CVSS: {cvss})
- Gói phần mềm / Ứng dụng: {package}
- Chi tiết: {title}

YÊU CẦU: Lập kế hoạch khắc phục sự cố NGẮN GỌN bằng tiếng Việt dưới 120 từ, trình bày theo HTML cơ bản (dùng <b>, <ul>, <li>), KHÔNG thêm lời chào hay giải thích dài dòng:
<b>1. Đánh giá rủi ro:</b> đúng 1 câu ngắn gọn về khả năng bị khai thác.
<b>2. Biện pháp vá lỗi (Patching):</b> tối đa 2 gạch đầu dòng (lệnh nâng cấp hoặc cập nhật phiên bản vá).
<b>3. Giảm thiểu tạm thời (Workaround):</b> tối đa 2 gạch đầu dòng (quy tắc tường lửa, tắt tính năng hoặc cấu hình an toàn)."""

    try:
        # Thử gọi Ollama
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False,
                "options": {"num_predict": 400, "temperature": 0.2}
            },
            timeout=45
        )
        if resp.status_code == 200:
            ai_text = resp.json().get("response", "")
            return jsonify({
                "status": "success",
                "cve_id": cve_id,
                "remediation_plan": ai_text
            })
        else:
            raise Exception(f"Ollama trả về mã {resp.status_code}")
    except Exception as e:
        logger.warning(f"Lỗi gọi Local LLM cho CVE {cve_id} ({e}), trả về kế hoạch mẫu chuẩn an toàn.")
        fallback_plan = f"""
        <b>1. Đánh giá rủi ro:</b> Lỗ hổng {cve_id} mức độ {severity} (CVSS {cvss}) có nguy cơ bị khai thác thực thi mã từ xa trên gói {package}.<br>
        <b>2. Biện pháp vá lỗi:</b>
        <ul>
            <li>Cập nhật {package} lên phiên bản mới nhất từ kho lưu trữ chính thức của nhà phát triển.</li>
            <li>Kiểm thử tính tương thích trên môi trường Staging trước khi triển khai Production.</li>
        </ul>
        <b>3. Giảm thiểu tạm thời:</b>
        <ul>
            <li>Giới hạn quyền truy cập mạng tới dịch vụ qua Tường lửa (Firewall / iptables).</li>
            <li>Theo dõi chặt chẽ log truy cập từ Wazuh SIEM để phát hiện hành vi thăm dò.</li>
        </ul>
        """
        return jsonify({
            "status": "success",
            "cve_id": cve_id,
            "remediation_plan": fallback_plan,
            "fallback": True
        })
