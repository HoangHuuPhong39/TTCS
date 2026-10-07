import json
import random

# Định nghĩa 4 kịch bản lõi trong báo cáo
attack_types = [
    {
        "type": "Port Scanning",
        "severity": "MEDIUM",
        "instruction": "Phân tích luồng log mạng sau: dest_port=17241, tcp_flags=SYN. Có dấu hiệu gì bất thường không?",
        "output": '{"severity": "MEDIUM", "attack_type": "Phân loại dò quét cổng (Port Scanning)", "findings": ["Hoạt động dò quét từ IP nguồn, mục đích thu thập thông tin hạ tầng."], "recommended_actions": ["Cấu hình Rate Limit", "Chặn IP trên Firewall"], "generated_query": "index=cic_ids sourcetype=\\"_json\\" dest_port=17241 | stats count by src_ip"}'
    },
    {
        "type": "Brute Force Attack",
        "severity": "HIGH",
        "instruction": "Phân tích luồng log mạng sau: dest_port=21, packet_count=5000 trong 1 phút. Có dấu hiệu gì bất thường không?",
        "output": '{"severity": "HIGH", "attack_type": "Phân loại dò mật khẩu (Brute Force Attack)", "findings": ["Hệ thống FTP bị tấn công thử credential liên tiếp."], "recommended_actions": ["Khóa tài khoản tạm thời", "Kích hoạt fail2ban"], "generated_query": "index=cic_ids sourcetype=\\"_json\\" dest_port=21 | stats count by src_ip"}'
    },
    {
        "type": "Heartbleed",
        "severity": "CRITICAL",
        "instruction": "Phân tích luồng log mạng sau: dest_port=444, giao thức mã hóa bất thường kéo dài. Có dấu hiệu gì không?",
        "output": '{"severity": "CRITICAL", "attack_type": "Heartbleed (CVE-2014-0160)", "findings": ["Dấu hiệu khai thác lỗ hổng TLS/SSL trên OpenSSL."], "recommended_actions": ["Cập nhật bản vá OpenSSL", "Thu hồi và cấp lại chứng chỉ SSL"], "generated_query": "index=cic_ids sourcetype=\\"_json\\" dest_port=444 | stats count by src_ip"}'
    },
    {
        "type": "DDoS",
        "severity": "CRITICAL",
        "instruction": "Phân tích luồng log mạng sau: dest_port=80, lưu lượng cực cao từ một IP duy nhất. Đánh giá sự cố?",
        "output": '{"severity": "CRITICAL", "attack_type": "Single Source Flood (DDoS)", "findings": ["Lưu lượng mạng tăng đột biến nhắm vào web server."], "recommended_actions": ["Kích hoạt Anti-DDoS", "Định tuyến lưu lượng qua Null-Route"], "generated_query": "index=cic_ids sourcetype=\\"_json\\" dest_port=80 | stats count by src_ip"}'
    }
]

dataset = []
print("[*] Đang khởi tạo tập dữ liệu huấn luyện...")

# Tự động sinh ra 350 mẫu (Trộn ngẫu nhiên 4 kịch bản)
for i in range(350):
    attack = random.choice(attack_types)
    
    # Biến tấu một chút IP hoặc Port để dữ liệu trông thật hơn
    fake_port = random.choice([21, 22, 80, 443, 3389, 444, 17241])
    instruction = attack["instruction"].replace("17241", str(fake_port)).replace("21", str(fake_port))
    
    # Đóng gói theo chuẩn hội thoại ChatML của Llama 3
    sample = {
        "messages": [
            {"role": "system", "content": "Bạn là chuyên gia phân tích SOC. Đầu ra BẮT BUỘC là định dạng JSON chuẩn."},
            {"role": "user", "content": instruction},
            {"role": "assistant", "content": attack["output"]}
        ]
    }
    dataset.append(sample)

# Xuất ra file JSONL
with open('data/soc_dataset_350.jsonl', 'w', encoding='utf-8') as f:
    for item in dataset:
        f.write(json.dumps(item, ensure_ascii=False) + '\n')

print("[+] Thành công! Đã xuất file soc_dataset_350.jsonl với 350 mẫu SOC chuẩn.")