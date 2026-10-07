"""
replay_eval.py - Script Đánh giá Thực nghiệm & Đo lường Hiệu năng AI (Có RAG vs Không RAG)
Dành cho đề tài Nghiên cứu phát triển Local LLM phục vụ ATTT (KMA SOC).

Mục tiêu khoa học:
1. Đo lường định lượng đóng góp của RAG (Retrieval-Augmented Generation) so với việc chỉ dùng LLM thuần.
2. Đánh giá trên tập dữ liệu đã gán nhãn (Ground Truth):
   - Từ SQLite DB (bảng alerts có evaluation = 'true_positive' / 'false_positive')
   - Hoặc từ file dataset mẫu 'data/soc_dataset_350.jsonl'
3. Tính toán ma trận nhầm lẫn (Confusion Matrix): TP, FP, TN, FN.
4. Tính toán các chỉ số: Precision, Recall, F1-Score, Accuracy và Average Latency.
5. Xuất báo cáo Markdown chi tiết để đưa trực tiếp vào Báo cáo TTCS / Khóa luận tốt nghiệp.

Cách chạy:
    python replay_eval.py --source dataset --limit 20
    python replay_eval.py --source db
    python replay_eval.py --model llama3 --limit 30
"""

import os
import sys
import json
import time
import sqlite3
import argparse
import requests
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "data", "soc_dataset_350.jsonl")
DB_PATH = os.path.join(BASE_DIR, "alerts_store.db")
CHROMA_DIR = os.path.join(BASE_DIR, "chroma_db")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")

# Nạp ChromaDB và Embedding nếu có
retriever = None
try:
    from langchain_community.embeddings import HuggingFaceEmbeddings
    from langchain_community.vectorstores import Chroma
    if os.path.exists(CHROMA_DIR) and os.listdir(CHROMA_DIR):
        emb = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        vdb = Chroma(persist_directory=CHROMA_DIR, embedding_function=emb)
        retriever = vdb.as_retriever(search_kwargs={"k": 2})
        print("[*] Kết nối ChromaDB Playbook thành công.")
    else:
        print("[!] Không tìm thấy thư mục ChromaDB cache, sẽ bỏ qua RAG hoặc dùng prompt chay.")
except Exception as e:
    print(f"[!] Cảnh báo nạp RAG: {e}. Vẫn có thể chạy đánh giá.")


def call_llm(prompt: str, model_name: str = "llama3") -> tuple[str, float]:
    """Gọi Ollama sinh kết quả và đo thời gian thực thi."""
    start = time.time()
    try:
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model": model_name,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 300}
            },
            timeout=60
        )
        latency = time.time() - start
        if resp.status_code == 200:
            return resp.json().get("response", ""), latency
        return "", latency
    except Exception as e:
        return "", time.time() - start


def parse_verdict(raw_text: str) -> str:
    """Chuẩn hóa kết quả đầu ra thành 'true_positive' hoặc 'false_positive'."""
    text = raw_text.lower()
    # Tìm kiếm nhãn rõ ràng
    if "true_positive" in text or "tấn công thật" in text or "mối đe dọa thật" in text or "critical" in text or "high" in text:
        return "true_positive"
    if "false_positive" in text or "báo động giả" in text or "hoạt động bình thường" in text or "an toàn" in text:
        return "false_positive"
    return "unknown"


def evaluate_sample(log_text: str, ground_truth: str, use_rag: bool, model_name: str) -> dict:
    rag_context = ""
    if use_rag and retriever:
        try:
            docs = retriever.invoke(log_text)
            rag_context = "\n".join([d.page_content for d in docs])
        except Exception:
            rag_context = ""

    if use_rag and rag_context:
        prompt = f"""Bạn là Chuyên gia SOC An ninh mạng. Hãy phân tích log cảnh báo sau đây dựa vào hướng dẫn Playbook nội bộ.
[PLAYBOOK NỘI BỘ]:
{rag_context}

[LOG CẢNH BÁO]:
{log_text}

Nhiệm vụ: Cảnh báo này là Tấn công thật (true_positive) hay Báo động giả (false_positive)?
Trả lời DUY NHẤT một dòng chứa từ khóa: 'true_positive' hoặc 'false_positive' kèm 1 câu lý do ngắn."""
    else:
        prompt = f"""Bạn là Chuyên gia SOC An ninh mạng. Hãy phân tích log cảnh báo sau đây:
[LOG CẢNH BÁO]:
{log_text}

Nhiệm vụ: Cảnh báo này là Tấn công thật (true_positive) hay Báo động giả (false_positive)?
Trả lời DUY NHẤT một dòng chứa từ khóa: 'true_positive' hoặc 'false_positive' kèm 1 câu lý do ngắn."""

    raw_resp, latency = call_llm(prompt, model_name)
    predicted = parse_verdict(raw_resp)
    return {
        "predicted": predicted,
        "is_correct": (predicted == ground_truth),
        "latency": latency,
        "raw_response": raw_resp.strip()
    }


def calculate_metrics(results: list[dict]) -> dict:
    tp = fp = tn = fn = unknown = 0
    total_time = 0.0

    for r in results:
        gt = r["ground_truth"]
        pred = r["predicted"]
        total_time += r["latency"]

        if pred == "true_positive":
            if gt == "true_positive":
                tp += 1
            else:
                fp += 1
        elif pred == "false_positive":
            if gt == "false_positive":
                tn += 1
            else:
                fn += 1
        else:
            unknown += 1

    total_valid = tp + fp + tn + fn
    accuracy = (tp + tn) / total_valid if total_valid > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    avg_latency = total_time / len(results) if results else 0.0

    return {
        "total": len(results),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "unknown": unknown,
        "accuracy": round(accuracy * 100, 2),
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "avg_latency": round(avg_latency, 2)
    }


def load_from_db(limit: int = 50) -> list[dict]:
    if not os.path.exists(DB_PATH):
        return []
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT description, full_log, evaluation FROM alerts
        WHERE evaluation IN ('true_positive', 'false_positive')
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    samples = []
    for r in rows:
        samples.append({
            "log": f"{r['description']} - Log: {r['full_log']}",
            "ground_truth": r['evaluation']
        })
    return samples


def load_from_dataset(limit: int = 50) -> list[dict]:
    if not os.path.exists(DATASET_PATH):
        return []
    samples = []
    with open(DATASET_PATH, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            data = json.loads(line)
            msgs = data.get("messages", [])
            user_msg = next((m["content"] for m in msgs if m["role"] == "user"), "")
            asst_msg = next((m["content"] for m in msgs if m["role"] == "assistant"), "")
            
            # Phán đoán nhãn từ dataset: CRITICAL/HIGH -> true_positive, LOW -> false_positive
            gt = "true_positive"
            if "LOW" in asst_msg or "Bình thường" in asst_msg:
                gt = "false_positive"

            samples.append({
                "log": user_msg,
                "ground_truth": gt
            })
            if len(samples) >= limit:
                break
    return samples


def main():
    parser = argparse.ArgumentParser(description="Chạy đối chứng đánh giá hiệu năng LLM (Có RAG vs Không RAG)")
    parser.add_argument("--source", choices=["dataset", "db"], default="dataset", help="Nguồn dữ liệu đánh giá")
    parser.add_argument("--limit", type=int, default=15, help="Số lượng mẫu kiểm thử (mặc định 15)")
    parser.add_argument("--model", type=str, default="llama3", help="Mô hình Ollama (llama3, qwen2.5, mistral...)")
    args = parser.parse_args()

    print(f"\n{'='*70}")
    print(f" ĐÁNH GIÁ THỰC NGHIỆM ĐỒ ÁN: ĐỐI CHỨNG RAG VS NO-RAG (Model: {args.model})")
    print(f"{'='*70}")

    if args.source == "db":
        samples = load_from_db(args.limit)
        print(f"[*] Đã tải {len(samples)} mẫu từ alerts_store.db")
    else:
        samples = load_from_dataset(args.limit)
        print(f"[*] Đã tải {len(samples)} mẫu từ {DATASET_PATH}")

    if not samples:
        print("[!] Không có dữ liệu kiểm thử. Vui lòng kiểm tra file dataset hoặc gán nhãn trong DB.")
        sys.exit(1)

    print(f"\n>>> 1. Đang chạy kiểm thử: CHẾ ĐỘ BASELINE (KHÔNG CÓ RAG)...")
    no_rag_results = []
    for i, s in enumerate(samples, 1):
        res = evaluate_sample(s["log"], s["ground_truth"], use_rag=False, model_name=args.model)
        res["ground_truth"] = s["ground_truth"]
        no_rag_results.append(res)
        print(f"   [{i}/{len(samples)}] GroundTruth: {s['ground_truth']:14} | AI đoán: {res['predicted']:14} | {'ĐÚNG' if res['is_correct'] else 'SAI'} ({res['latency']:.1f}s)")

    print(f"\n>>> 2. Đang chạy kiểm thử: CHẾ ĐỘ ENHANCED (CÓ RAG PLAYBOOK)...")
    rag_results = []
    for i, s in enumerate(samples, 1):
        res = evaluate_sample(s["log"], s["ground_truth"], use_rag=True, model_name=args.model)
        res["ground_truth"] = s["ground_truth"]
        rag_results.append(res)
        print(f"   [{i}/{len(samples)}] GroundTruth: {s['ground_truth']:14} | AI đoán: {res['predicted']:14} | {'ĐÚNG' if res['is_correct'] else 'SAI'} ({res['latency']:.1f}s)")

    m_no_rag = calculate_metrics(no_rag_results)
    m_rag = calculate_metrics(rag_results)

    # In kết quả dạng bảng Markdown
    report_md = f"""
### BẢNG KẾT QUẢ ĐỐI CHỨNG THỰC NGHIỆM ĐỒ ÁN
**Mô hình đánh giá:** {args.model} | **Số lượng mẫu:** {len(samples)} | **Thời gian:** {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}

| Chỉ số đánh giá | Baseline (Không RAG) | Enhanced (Có RAG Playbook) | Chênh lệch (+/-) |
| :--- | :---: | :---: | :---: |
| **Accuracy (Độ chính xác)** | {m_no_rag['accuracy']}% | **{m_rag['accuracy']}%** | **+{round(m_rag['accuracy'] - m_no_rag['accuracy'], 2)}%** |
| **Precision (Độ chuẩn xác)** | {m_no_rag['precision']}% | **{m_rag['precision']}%** | **+{round(m_rag['precision'] - m_no_rag['precision'], 2)}%** |
| **Recall (Độ nhạy/Bao phủ)** | {m_no_rag['recall']}% | **{m_rag['recall']}%** | **+{round(m_rag['recall'] - m_no_rag['recall'], 2)}%** |
| **F1-Score (F-điểm điều hòa)** | {m_no_rag['f1_score']}% | **{m_rag['f1_score']}%** | **+{round(m_rag['f1_score'] - m_no_rag['f1_score'], 2)}%** |
| **Độ trễ TB (Latency)** | {m_no_rag['avg_latency']}s | {m_rag['avg_latency']}s | +{round(m_rag['avg_latency'] - m_no_rag['avg_latency'], 2)}s |
| **True Positive (TP)** | {m_no_rag['tp']} | {m_rag['tp']} | - |
| **False Positive (FP)** | {m_no_rag['fp']} | {m_rag['fp']} | - |
| **True Negative (TN)** | {m_no_rag['tn']} | {m_rag['tn']} | - |
| **False Negative (FN)** | {m_no_rag['fn']} | {m_rag['fn']} | - |
"""
    print(report_md)

    # Lưu kết quả ra file txt/md để tiện chèn vào báo cáo
    out_file = os.path.join(BASE_DIR, "reports", "KetQuaDanhGia_RAG.md")
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(report_md)
    print(f"[*] Đã xuất kết quả thực nghiệm ra file: {out_file}")


if __name__ == "__main__":
    main()
