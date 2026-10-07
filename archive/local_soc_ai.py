import os
from langchain_community.llms import Ollama
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough

# ==========================================
# 1. KHỞI TẠO LOCAL LLM & EMBEDDING
# ==========================================
print("[*] Đang nạp mô hình Local LLM (Llama 3)...")
llm = Ollama(model="llama3")

print("[*] Đang nạp mô hình Embedding Offline...")
# Sử dụng mô hình all-MiniLM-L6-v2 siêu nhẹ, chạy hoàn toàn offline
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

# ==========================================
# 2. XÂY DỰNG RAG & VECTOR DATABASE
# ==========================================
print("[*] Đang đọc Playbook và nạp vào Vector Database...")
# Đọc file Playbook nội bộ
loader = TextLoader(r"D:\TTCS\TTCS\data\SOC_Playbook.txt", encoding="utf-8")
docs = loader.load()

# Cắt nhỏ văn bản (Chunking) để tối ưu cho việc tìm kiếm Vector
text_splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
chunks = text_splitter.split_documents(docs)

# Tạo Vector Database (ChromaDB) lưu cục bộ trên RAM
vector_db = Chroma.from_documents(documents=chunks, embedding=embeddings)

# Tạo bộ truy xuất (Retriever) lấy 2 đoạn văn bản liên quan nhất
retriever = vector_db.as_retriever(search_kwargs={"k": 2})

# ==========================================
# 3. TÍNH NĂNG 1: RAG - HỎI ĐÁP DỰA TRÊN PLAYBOOK
# ==========================================
rag_prompt = PromptTemplate.from_template(
    """Bạn là chuyên gia SOC. Dựa vào tài liệu nội bộ sau đây, hãy trả lời câu hỏi. 
    Nếu không có trong tài liệu, hãy nói "Tôi không tìm thấy thông tin trong Playbook".
    
    Tài liệu (Context):
    {context}
    
    Câu hỏi: {question}
    
    Trả lời bằng tiếng Việt:"""
)

rag_chain = (
    {"context": retriever, "question": RunnablePassthrough()}
    | rag_prompt
    | llm
    | StrOutputParser()
)

# ==========================================
# 4. TÍNH NĂNG 2: SINH CÂU LỆNH TRUY VẤN (QUERY GENERATION)
# ==========================================
query_prompt = PromptTemplate.from_template(
    """Bạn là chuyên gia về SIEM (Wazuh/Elasticsearch).
    Nhiệm vụ của bạn là chuyển đổi ngôn ngữ tự nhiên của SOC Analyst thành câu lệnh truy vấn Elasticsearch / KQL (Kibana Query Language).
    Chỉ trả về câu lệnh code, không cần giải thích dài dòng.
    
    Ví dụ: "Tìm các đăng nhập thất bại từ IP 1.2.3.4"
    Kết quả: rule.id: "5716" AND srcip: "1.2.3.4"
    
    Yêu cầu từ Analyst: {natural_language}
    Kết quả câu lệnh truy vấn:"""
)

query_chain = query_prompt | llm | StrOutputParser()

# ==========================================
# CHẠY THỬ NGHIỆM
# ==========================================
if __name__ == "__main__":
    print("\n" + "="*70)
    print("PHẦN 1: DEMO RAG - AI TRỢ LÝ PHÂN TÍCH THEO PLAYBOOK SOC")
    print("="*70)
    
    # Danh sách các câu hỏi test 3 kịch bản tấn công khác nhau
    rag_questions = [
        "1. Nếu tôi phát hiện IP 192.168.1.100 đăng nhập thất bại liên tục, tôi phải làm gì?",
        "2. Hệ thống cảnh báo Event ID 4732 (thêm quyền Admin) với một tài khoản lạ. Xử lý sao đây?",
        "3. Tôi thấy Event ID 1102 báo log đã bị xóa. Theo Playbook đây là lỗi nhẹ hay nghiêm trọng?"
    ]
    
    for q in rag_questions:
        print(f"\n[👨‍💻 SOC Analyst hỏi]: {q}")
        print("-" * 50)
        rag_response = rag_chain.invoke(q)
        print(f"[🤖 Llama 3 trả lời]:\n{rag_response}")


    print("\n" + "="*70)
    print("PHẦN 2: DEMO QUERY GENERATION - AI TỰ ĐỘNG SINH LỆNH SIEM")
    print("="*70)
    
    # Danh sách các yêu cầu sinh câu lệnh truy vấn
    nl_queries = [
        "1. Tìm các đăng nhập thành công (Event 4624) trên máy chủ WIN-SRV-01.",
        "2. Lọc ra các log Brute-force (Event 4625) đến từ IP 10.0.0.5.",
        "3. Lấy ra các log xóa dấu vết (Event 1102) do tài khoản 'backdoor' làm."
    ]
    
    for nq in nl_queries:
        print(f"\n[👨‍💻 Analyst yêu cầu]: {nq}")
        print("-" * 50)
        query_response = query_chain.invoke({"natural_language": nq})
        print(f"[⚡ Lệnh KQL sinh ra]:\n{query_response}")
        
    print("\n" + "="*70)
    print("HOÀN TẤT DEMO HỆ THỐNG SOC AI LOCAL!")