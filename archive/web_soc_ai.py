import os
from flask import Flask, request, jsonify, render_template_string
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
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

# ==========================================
# 2. XÂY DỰNG RAG & VECTOR DATABASE
# ==========================================
print("[*] Đang đọc Playbook và nạp vào Vector Database...")
# LƯU Ý: Sửa lại đường dẫn này nếu file của bạn để ở chỗ khác
loader = TextLoader(r"D:\TTCS\TTCS\data\SOC_Playbook.txt", encoding="utf-8")
docs = loader.load()

text_splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
chunks = text_splitter.split_documents(docs)

vector_db = Chroma.from_documents(documents=chunks, embedding=embeddings)
retriever = vector_db.as_retriever(search_kwargs={"k": 2})

# ==========================================
# 3. SETUP PROMPTS & CHAINS
# ==========================================
rag_prompt = PromptTemplate.from_template(
    """Bạn là chuyên gia SOC. Dựa vào tài liệu nội bộ sau đây, hãy trả lời câu hỏi. 
    Nếu không có trong tài liệu, hãy nói "Tôi không tìm thấy thông tin trong Playbook".
    
    Tài liệu (Context):
    {context}
    
    Câu hỏi: {question}
    
    Trả lời bằng tiếng Việt:"""
)
rag_chain = {"context": retriever, "question": RunnablePassthrough()} | rag_prompt | llm | StrOutputParser()

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
# 4. KHỞI TẠO WEB SERVER (FLASK) & GIAO DIỆN
# ==========================================
app = Flask(__name__)

# --- GIAO DIỆN HTML/CSS/JS (Nằm gọn trong biến này) ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KMA SOC AI - Local LLM</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .glass-panel { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border: 1px solid #334155; }
        .loading-spinner { border: 3px solid rgba(255,255,255,0.1); border-radius: 50%; border-top: 3px solid #10b981; width: 20px; height: 20px; animation: spin 1s linear infinite; display: none;}
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .code-block { background-color: #1e293b; padding: 1rem; border-radius: 0.5rem; font-family: monospace; color: #38bdf8; border-left: 4px solid #0ea5e9;}
    </style>
</head>
<body class="min-h-screen flex flex-col p-6">
    
    <!-- Header -->
    <header class="flex items-center justify-between mb-8 pb-4 border-b border-slate-700">
        <div class="flex items-center gap-4">
            <div class="p-3 bg-indigo-600 rounded-lg shadow-lg shadow-indigo-500/30">
                <i class="fa-solid fa-shield-halved text-2xl text-white"></i>
            </div>
            <div>
                <h1 class="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 to-cyan-400">SOC AI - LOCAL LLM</h1>
                <p class="text-slate-400 text-sm">Offline Security Operations Center - KMA</p>
            </div>
        </div>
        <div class="flex items-center gap-2 bg-emerald-500/10 text-emerald-400 px-3 py-1.5 rounded-full border border-emerald-500/20">
            <div class="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></div>
            <span class="text-sm font-semibold">Llama 3 & RAG Active</span>
        </div>
    </header>

    <!-- Main Content -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-6 flex-grow">
        
        <!-- MODULE 1: RAG PLAYBOOK -->
        <div class="glass-panel rounded-xl p-6 flex flex-col shadow-xl">
            <h2 class="text-xl font-bold mb-2 flex items-center gap-2 text-indigo-300">
                <i class="fa-solid fa-book-open"></i> Trợ Lý Phân Tích (RAG)
            </h2>
            <p class="text-slate-400 text-sm mb-4 border-b border-slate-700 pb-4">Hỏi đáp dựa trên tri thức nội bộ từ SOC Playbook.</p>
            
            <div class="flex-grow flex flex-col gap-4">
                <textarea id="rag-input" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg p-3 text-white focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 resize-none h-32" placeholder="Ví dụ: Dấu hiệu của tấn công Brute-force là gì? Tôi cần làm những bước nào tiếp theo?"></textarea>
                <button onclick="askRAG()" class="bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2 px-4 rounded-lg transition-all flex items-center justify-center gap-2">
                    <i class="fa-solid fa-paper-plane"></i> Gửi Yêu Cầu RAG
                    <div id="rag-spinner" class="loading-spinner"></div>
                </button>
                <div class="mt-2 flex-grow flex flex-col">
                    <h3 class="text-sm font-semibold text-slate-400 mb-2">Kết quả phân tích:</h3>
                    <div id="rag-output" class="bg-slate-800/50 border border-slate-700 rounded-lg p-4 flex-grow text-slate-200 whitespace-pre-wrap overflow-y-auto max-h-64 h-full">...</div>
                </div>
            </div>
        </div>

        <!-- MODULE 2: QUERY GENERATOR -->
        <div class="glass-panel rounded-xl p-6 flex flex-col shadow-xl">
            <h2 class="text-xl font-bold mb-2 flex items-center gap-2 text-cyan-300">
                <i class="fa-solid fa-terminal"></i> Sinh Truy Vấn SIEM (KQL)
            </h2>
            <p class="text-slate-400 text-sm mb-4 border-b border-slate-700 pb-4">Chuyển ngôn ngữ tự nhiên thành câu lệnh kỹ thuật.</p>
            
            <div class="flex-grow flex flex-col gap-4">
                <textarea id="query-input" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg p-3 text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 resize-none h-32" placeholder="Ví dụ: Tìm cho tôi các đăng nhập thành công (Event 4624) từ máy chủ có tên WIN-SRV-01."></textarea>
                <button onclick="generateQuery()" class="bg-cyan-600 hover:bg-cyan-500 text-white font-bold py-2 px-4 rounded-lg transition-all flex items-center justify-center gap-2">
                    <i class="fa-solid fa-code"></i> Sinh Câu Lệnh KQL
                    <div id="query-spinner" class="loading-spinner"></div>
                </button>
                <div class="mt-2 flex-grow flex flex-col">
                    <h3 class="text-sm font-semibold text-slate-400 mb-2">Câu lệnh sinh ra:</h3>
                    <div id="query-output" class="bg-slate-800/50 border border-slate-700 rounded-lg p-4 flex-grow overflow-y-auto max-h-64 h-full flex items-center justify-center text-slate-500">
                        Chưa có dữ liệu
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Script xử lý kết nối Web với Python -->
    <script>
        async function askRAG() {
            const input = document.getElementById('rag-input').value;
            const outputDiv = document.getElementById('rag-output');
            const spinner = document.getElementById('rag-spinner');
            
            if(!input) return alert("Vui lòng nhập câu hỏi!");
            
            outputDiv.innerHTML = '<span class="text-slate-500 italic">Đang suy luận từ Playbook (mất vài giây)...</span>';
            spinner.style.display = 'block';

            try {
                const response = await fetch('/api/rag', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ question: input })
                });
                const data = await response.json();
                outputDiv.innerHTML = data.answer;
            } catch (error) {
                outputDiv.innerHTML = `<span class="text-red-400">Lỗi kết nối: ${error.message}</span>`;
            }
            spinner.style.display = 'none';
        }

        async function generateQuery() {
            const input = document.getElementById('query-input').value;
            const outputDiv = document.getElementById('query-output');
            const spinner = document.getElementById('query-spinner');
            
            if(!input) return alert("Vui lòng nhập yêu cầu!");
            
            outputDiv.innerHTML = '<span class="text-slate-500 italic">Đang biên dịch sang KQL...</span>';
            spinner.style.display = 'block';

            try {
                const response = await fetch('/api/query', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ question: input })
                });
                const data = await response.json();
                outputDiv.innerHTML = `<div class="code-block w-full">${data.answer}</div>`;
            } catch (error) {
                outputDiv.innerHTML = `<span class="text-red-400">Lỗi kết nối: ${error.message}</span>`;
            }
            spinner.style.display = 'none';
        }
    </script>
</body>
</html>
"""

# Route hiển thị giao diện trang Web
@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

# Route xử lý API cho tính năng RAG
@app.route('/api/rag', methods=['POST'])
def api_rag():
    data = request.json
    question = data.get("question", "")
    try:
        # Gọi mô hình LLM nội bộ
        answer = rag_chain.invoke(question)
        return jsonify({"answer": answer})
    except Exception as e:
        return jsonify({"answer": f"Lỗi AI: {str(e)}"}), 500

# Route xử lý API cho tính năng sinh lệnh
@app.route('/api/query', methods=['POST'])
def api_query():
    data = request.json
    question = data.get("question", "")
    try:
        # Gọi mô hình LLM nội bộ
        answer = query_chain.invoke({"natural_language": question})
        return jsonify({"answer": answer})
    except Exception as e:
        return jsonify({"answer": f"Lỗi AI: {str(e)}"}), 500

if __name__ == "__main__":
    print("\n" + "="*70)
    print("🚀 MÁY CHỦ WEB SOC AI (LOCAL LLM) ĐÃ SẴN SÀNG!")
    print("👉 HÃY MỞ TRÌNH DUYỆT VÀ TRUY CẬP: http://127.0.0.1:5002")
    print("="*70 + "\n")
    # Đổi sang port 5002 để không trùng với SOC Dashboard chính
    app.run(host="127.0.0.1", port=5002, debug=False)