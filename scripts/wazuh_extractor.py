import requests
import json
import urllib3
import os
import markdown
from datetime import datetime
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# 1. CẤU HÌNH HỆ THỐNG
# ==========================================
WAZUH_IP = os.getenv("WAZUH_IP", "192.168.1.100")
PORT = int(os.getenv("WAZUH_PORT", "9200"))
USERNAME = os.getenv("WAZUH_USER", "admin")
PASSWORD = os.getenv("WAZUH_PASS", "password")
os.environ["GOOGLE_API_KEY"] = os.getenv("GOOGLE_API_KEY", "")

# Lấy thời gian hiện tại để đặt tên file
current_time = datetime.now()
date_str = current_time.strftime("%d_%m_%Y")
time_str = current_time.strftime("%H:%M:%S - %d/%m/%Y")

url = f"https://{WAZUH_IP}:{PORT}/wazuh-alerts-*/_search"

query = {
    "size": 5, 
    "sort": [{"timestamp": {"order": "desc"}}],
    "query": {"range": {"rule.level": {"gte": 7}}}
}
headers = {'Content-Type': 'application/json'}

def export_to_html(md_text, filename):
    """Hàm biến văn bản thô của AI thành file Báo cáo tuyệt đẹp"""
    html_content = markdown.markdown(md_text)
    
    # Thiết kế giao diện báo cáo CSS
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
    
    # Lưu ra file HTML
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(full_html)
    print(f"[+] Đã xuất báo cáo thành công tại: {filename}")
    print("[Mẹo] Bạn hãy click đúp vào file HTML này để mở bằng Chrome, sau đó ấn Ctrl + P để lưu thành file PDF cực đẹp nhé!")

def fetch_and_analyze():
    print("[*] Đang kéo log và nhờ AI phân tích...")
    try:
        response = requests.post(url, auth=(USERNAME, PASSWORD), headers=headers, data=json.dumps(query), verify=False)
        
        if response.status_code == 200:
            alerts = response.json()['hits']['hits']
            if not alerts:
                print("[-] Không có cảnh báo.")
                return

            alerts_text = "".join([f"- Cảnh báo: {a['_source'].get('rule', {}).get('description')} tại {a['_source'].get('agent', {}).get('name')}\n" for a in alerts])
            
            # Khởi tạo siêu mô hình
            llm = ChatGoogleGenerativeAI(model="models/gemini-3.5-flash", temperature=0.2)
            
            template = "Dựa trên các log: {alerts_data}. Hãy viết Báo cáo sự cố an ninh bằng tiếng Việt, trình bày Markdown với 3 phần: 1. Tóm tắt, 2. Đánh giá rủi ro, 3. Đề xuất khắc phục."
            prompt = PromptTemplate(input_variables=["alerts_data"], template=template)
            
            report = (prompt | llm).invoke({"alerts_data": alerts_text})
            
            # Xử lý kết quả trả về từ AI
            report_text = report.content[0]['text'] if isinstance(report.content, list) else report.content
            
            # Đảm bảo thư mục reports tồn tại trước khi lưu
            import os
            if not os.path.exists("reports"):
                os.makedirs("reports")

            # 1. Sửa lại đường dẫn lưu file Markdown
            md_filename = f"reports/SOC_Report_{date_str}.md"
            with open(md_filename, 'w', encoding='utf-8') as f:
                f.write(report_text)

            # 2. Sửa lại đường dẫn file HTML Báo cáo giao diện đẹp
            html_filename = f"reports/SOC_Report_{date_str}.html"
            export_to_html(report_text, html_filename)
            
        else:
            print("[-] Lỗi API")
    except Exception as e:
        print(f"[-] Lỗi: {e}")

if __name__ == "__main__":
    fetch_and_analyze()