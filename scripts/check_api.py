import os
import requests
import urllib3
from langchain_google_genai import ChatGoogleGenerativeAI

# Tắt cảnh báo SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# CẤU HÌNH THÔNG SỐ KIỂM TRA
# ==========================================
WAZUH_IP = os.getenv("WAZUH_IP", "192.168.1.100")
PORT = int(os.getenv("WAZUH_PORT", "9200"))
USERNAME = os.getenv("WAZUH_USER", "admin")
PASSWORD = os.getenv("WAZUH_PASS", "password")
GEMINI_API_KEY = os.getenv("GOOGLE_API_KEY", "") # Lay tu bien moi truong

def check_wazuh_connection():
    print("[*] Đang kiểm tra kết nối tới Máy chủ Wazuh SIEM...")
    # Kiểm tra endpoint cơ bản của Elastic/Wazuh Indexer
    url = f"https://{WAZUH_IP}:{PORT}/"
    try:
        response = requests.get(url, auth=(USERNAME, PASSWORD), verify=False, timeout=5)
        if response.status_code in [200, 401, 403]:
            print(f"  [+] Thành công! Wazuh đang hoạt động (HTTP {response.status_code}).")
        else:
            print(f"  [-] Máy chủ có phản hồi nhưng trả về mã lỗi: HTTP {response.status_code}")
    except requests.exceptions.Timeout:
        print("  [-] Lỗi: Hết thời gian chờ (Timeout). Hãy kiểm tra lại IP máy ảo.")
    except Exception as e:
        print(f"  [-] Không thể kết nối tới Wazuh. Lỗi: {e}")

def check_gemini_api():
    print("\n[*] Đang kiểm tra kết nối tới Google Gemini API...")
    os.environ["GOOGLE_API_KEY"] = GEMINI_API_KEY
    try:
        # Khởi tạo mô hình
        llm = ChatGoogleGenerativeAI(model="models/gemini-3.5-flash", temperature=0.2)
        # Gửi một prompt test cực ngắn
        res = llm.invoke("Hãy trả lời chính xác 3 chữ: 'API Hoạt Động'")
        print(f"  [+] Thành công! Gemini phản hồi: {str(res.content)}")
    except Exception as e:
        print(f"  [-] Lỗi Gemini API (Kiểm tra lại Key hoặc mạng): {e}")

if __name__ == "__main__":
    print("\n" + "="*60)
    print(" CÔNG CỤ KIỂM TRA TRẠNG THÁI HỆ THỐNG KMA SOC ".center(60, "="))
    print("="*60 + "\n")
    
    check_wazuh_connection()
    check_gemini_api()
    
    print("\n" + "="*60 + "\n")