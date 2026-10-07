# Local AI SOC Copilot - Tích hợp Wazuh SIEM & RAG qua Ollama

Hệ thống hỗ trợ phân tích cảnh báo an toàn thông tin (Security Operations Center - SOC) sử dụng mô hình ngôn ngữ lớn cục bộ (**Local LLM qua Ollama**) kết hợp kỹ thuật **RAG (Retrieval-Augmented Generation)** và **Wazuh SIEM**.

Hệ thống hoạt động hoàn toàn **On-Premise / Local**, bảo đảm tính toàn vẹn và chủ quyền dữ liệu (Data Sovereignty), không gửi log nhạy cảm ra ngoài Internet.

---

## Tính năng chính

- **Tích hợp Wazuh SIEM:** Thu thập và chuẩn hóa log cảnh báo thời gian thực từ Wazuh Indexer / Elasticsearch.
- **Phân tích bằng Local LLM:** Sử dụng Ollama (Qwen2, Llama3, Mistral,...) phân tích nguyên nhân tấn công, mức độ nghiêm trọng và khuyến nghị ứng phó bằng tiếng Việt.
- **RAG với ChromaDB:** Tích hợp tri thức chuyên ngành an toàn thông tin (SOC Playbooks, MITRE ATT&CK, CVE) giúp giảm thiểu hiện tượng ảo giác (hallucination).
- **Incident Correlator:** Tương quan chuỗi sự kiện tấn công theo địa chỉ IP và dòng thời gian.
- **Bảng điều khiển SOC trực quan:** Dashboard giao diện Web hỗ trợ chuyên viên SOC giám sát, lọc cảnh báo, xuất báo cáo và tương tác trợ lý AI.

---

## Kiến trúc hệ thống

```text
+------------------+         +--------------------+         +-------------------+
|   Wazuh Agent    | ------> |    Wazuh Server    | ------> |   Wazuh Indexer   |
| (Endpoints/Logs) |         | (Rule engine SIEM) |         |  (Elasticsearch)  |
+------------------+         +--------------------+         +-------------------+
                                                                      |
                                                                      v
                                                            +-------------------+
                                                            |  SOC AI Gateway   |
                                                            | (app_dashboard.py)|
                                                            +-------------------+
                                                                 /         \
                                        (Truy xuất Playbook)    /           \ (Phân tích ngữ cảnh)
                                                               v             v
                                                      +------------+     +------------+
                                                      |  ChromaDB  |     |   Ollama   |
                                                      | (Vector DB)|     | (Local LLM)|
                                                      +------------+     +------------+
```

---

## Yêu cầu môi trường

- **Hệ điều hành:** Linux (Ubuntu 22.04+) hoặc Windows 10/11
- **Python:** 3.10 trở lên
- **Ollama:** Cài đặt từ [ollama.com](https://ollama.com) và tải mô hình (ví dụ: `ollama run qwen2:7b` hoặc `ollama run llama3:8b`)
- **Wazuh SIEM:** Máy chủ Wazuh đang hoạt động với API / Elasticsearch port 9200

---

## Hướng dẫn cài đặt & Chạy ứng dụng

### 1. Clone repository
```bash
git clone [https://github.com/<your-username>/<repo-name>.git](https://github.com/HoangHuuPhong39/TTCS.git)
cd <repo-name>
```

### 2. Tạo môi trường ảo và cài đặt thư viện
```bash
python -m venv venv
# Trên Windows:
.\venv\Scripts\activate
# Trên Linux:
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Cấu hình biến môi trường
Tạo file `.env` từ mẫu `.env.example`:
```bash
cp .env.example .env
```
Mở `.env` và chỉnh sửa thông tin kết nối tới Wazuh SIEM:
```ini
WAZUH_IP=192.168.1.100
WAZUH_PORT=9200
WAZUH_USER=admin
WAZUH_PASS=YourStrongPasswordHere
PLAYBOOK_PATH=./data/SOC_Playbook.txt
```

### 4. Khởi chạy ứng dụng Dashboard
```bash
python app_dashboard.py
```
Truy cập giao diện Web tại địa chỉ: `http://localhost:5000` (hoặc cổng cấu hình tương ứng).

---

## Cấu trúc thư mục

```text
.
├── .env.example               # Mẫu cấu hình môi trường
├── .gitignore                 # Các file bỏ qua không commit lên Git
├── README.md                  # Tài liệu hướng dẫn dự án
├── requirements.txt           # Danh sách thư viện Python
├── app_dashboard.py           # Ứng dụng chính (Flask / Dashboard & AI Gateway)
├── incident_correlator.py     # Module tương quan sự cố an ninh
├── replay_eval.py             # Script đánh giá và kiểm thử log
├── vulns_blueprint.py         # Blueprint quản lý lỗ hổng bảo mật
├── generate_dataset.py        # Script sinh tập dữ liệu mẫu
├── data/                      # Dữ liệu mẫu và Playbook tri thức
│   ├── SOC_Playbook.txt
│   └── soc_dataset_350.jsonl
├── diagrams/                  # Sơ đồ kiến trúc & luồng xử lý hệ thống
├── templates/                 # Giao diện HTML của Dashboard
├── scripts/                   # Các script tiện ích bổ trợ
└── baocao/                    # Báo cáo thực tập & đề cương (.docx)
```

---

## Giấy phép
Dự án được xây dựng phục vụ nghiên cứu học thuật và thực tập cơ sở ngành An toàn Thông tin.
