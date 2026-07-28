import streamlit as st
import os
import sys
from datetime import datetime
from dotenv import load_dotenv

# Thêm src vào Python path để import được các module
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from core.chatbot import create_encrypted_chatbot, EncryptedChatbot
from database.models import Session

# Load environment variables
load_dotenv()

# Cấu hình trang
st.set_page_config(
    page_title="Encrypted Chatbot",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.warning("⚠️ LEGACY INSECURE LAB: Vigenère/Streamlit chỉ dùng để so sánh học thuật. Không nhập dữ liệu thật và không triển khai Internet.")

# Custom CSS
st.markdown("""
<style>
    .chat-message {
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
        display: flex;
        flex-direction: column;
    }
    .user-message {
        background-color: #e3f2fd;
        margin-left: 20%;
    }
    .assistant-message {
        background-color: #f5f5f5;
        margin-right: 20%;
    }
    .message-header {
        font-weight: bold;
        margin-bottom: 0.5rem;
        font-size: 0.9rem;
    }
    .message-content {
        font-size: 1rem;
        line-height: 1.4;
    }
    .session-item {
        padding: 0.5rem;
        border-radius: 0.3rem;
        margin-bottom: 0.5rem;
        cursor: pointer;
        border: 1px solid #ddd;
    }
    .session-item:hover {
        background-color: #f0f0f0;
    }
    .active-session {
        background-color: #e3f2fd;
        border-color: #2196f3;
    }
</style>
""", unsafe_allow_html=True)

def initialize_session_state():
    """Khởi tạo session state."""
    if 'chatbot' not in st.session_state:
        st.session_state.chatbot = None
    if 'current_session_id' not in st.session_state:
        st.session_state.current_session_id = None
    if 'sessions' not in st.session_state:
        st.session_state.sessions = []
    if 'messages' not in st.session_state:
        st.session_state.messages = []
    if 'raw_messages' not in st.session_state:
        st.session_state.raw_messages = []
    if 'encryption_key' not in st.session_state:
        st.session_state.encryption_key = "DEFAULTKEY"

def create_chatbot_instance(encryption_key: str, encryption_mode: str, db_path: str):
    """Tạo instance chatbot."""
    try:
        chatbot = create_encrypted_chatbot(
            db_path=db_path,
            encryption_key=encryption_key,
            encryption_mode=encryption_mode,
            gemini_api_key=None,  # Sẽ đọc từ environment
            gemini_model="gemini-2.5-flash-lite"
        )
        return chatbot
    except Exception as e:
        st.error(f"Lỗi tạo chatbot: {e}")
        return None

def load_sessions(chatbot: EncryptedChatbot):
    """Tải danh sách phiên hội thoại."""
    try:
        sessions = chatbot.list_sessions(limit=50)
        return sessions
    except Exception as e:
        st.error(f"Lỗi tải phiên: {e}")
        return []

def load_messages(chatbot: EncryptedChatbot, session_id: str):
    """Tải tin nhắn trong phiên."""
    try:
        messages = chatbot.get_decrypted_history(session_id)
        return messages
    except Exception as e:
        st.error(f"Lỗi tải tin nhắn: {e}")
        return []

def render_message(message, key):
    """Render một tin nhắn."""
    is_user = message.role.value == "user"
    css_class = "user-message" if is_user else "assistant-message"
    role_name = "Bạn" if is_user else "AI"
    
    st.markdown(f"""
    <div class="chat-message {css_class}">
        <div class="message-header">{role_name} • {message.created_at.strftime('%H:%M:%S')}</div>
        <div class="message-content">{message.content}</div>
    </div>
    """, unsafe_allow_html=True)

def sidebar_config():
    """Thanh bên cấu hình."""
    st.sidebar.title("🔐 Cấu Hình Chatbot")
    
    # API Key check
    api_key = os.getenv("GOOGLE_GENAI_API_KEY")
    if api_key:
        st.sidebar.success("✅ Google GenAI API Key đã được thiết lập")
    else:
        st.sidebar.error("❌ Chưa có Google GenAI API Key")
        st.sidebar.info("Thiết lập biến môi trường GOOGLE_GENAI_API_KEY")
    
    # Cấu hình mã hóa
    st.sidebar.subheader("Mã Hóa")
    encryption_key = st.sidebar.text_input(
        "Khóa mã hóa:",
        value=st.session_state.encryption_key,
        type="password",
        help="Khóa sử dụng cho Vigenère Autokey"
    )
    
    encryption_mode = st.sidebar.selectbox(
        "Chế độ Autokey:",
        ["plaintext", "ciphertext"],
        help="plaintext: dùng bản rõ mở rộng keystream\nciphertext: dùng bản mã mở rộng keystream"
    )
    
    db_path = st.sidebar.text_input(
        "Đường dẫn Database:",
        value="encrypted_chat.db",
        help="File SQLite lưu trữ tin nhắn đã mã hóa"
    )
    
    # Nút tạo chatbot
    if st.sidebar.button("🔄 Khởi tạo Chatbot", type="primary"):
        if encryption_key.strip():
            st.session_state.encryption_key = encryption_key
            chatbot = create_chatbot_instance(encryption_key, encryption_mode, db_path)
            if chatbot:
                st.session_state.chatbot = chatbot
                st.session_state.sessions = load_sessions(chatbot)
                st.sidebar.success("Chatbot đã được khởi tạo!")
                st.rerun()
        else:
            st.sidebar.error("Vui lòng nhập khóa mã hóa!")
    
    return encryption_key, encryption_mode, db_path

def sidebar_sessions():
    """Quản lý phiên hội thoại."""
    if not st.session_state.chatbot:
        return
        
    st.sidebar.subheader("💬 Phiên Hội Thoại")
    
    # Nút tạo phiên mới
    col1, col2 = st.sidebar.columns(2)
    with col1:
        if st.button("➕ Phiên mới"):
            try:
                session_title = f"Chat {datetime.now().strftime('%H:%M:%S')}"
                new_session = st.session_state.chatbot.start_session(session_title)
                st.session_state.current_session_id = new_session.id
                st.session_state.sessions = load_sessions(st.session_state.chatbot)
                st.session_state.messages = []
                st.session_state.raw_messages = []
                st.rerun()
            except Exception as e:
                _ = st.error(f"Lỗi tạo phiên: {e}")
    
    with col2:
        if st.button("🔄 Làm mới"):
            st.session_state.sessions = load_sessions(st.session_state.chatbot)
            st.rerun()
    
    # Danh sách phiên
    if st.session_state.sessions:
        st.sidebar.write("**Chọn phiên:**")
        for session in st.session_state.sessions:
            is_active = session.id == st.session_state.current_session_id
            css_class = "active-session" if is_active else ""
            
            if st.sidebar.button(
                f"📝 {session.title or 'Phiên không có tiêu đề'}",
                key=f"session_{session.id}",
                help=f"Tạo: {session.created_at.strftime('%Y-%m-%d %H:%M:%S')}"
            ):
                st.session_state.current_session_id = session.id
                st.session_state.messages = load_messages(st.session_state.chatbot, session.id)
                st.session_state.raw_messages = load_raw_messages(st.session_state.chatbot, session.id)
                st.rerun()
    else:
        st.sidebar.info("Chưa có phiên nào. Tạo phiên mới để bắt đầu!")

def load_raw_messages(chatbot: EncryptedChatbot, session_id: str) -> list:
    """Tải tin nhắn thô (đã mã hóa) từ database."""
    try:
        # Sử dụng database trực tiếp để lấy tin nhắn đã mã hóa
        raw_messages = chatbot.db.fetch_messages(session_id, order="asc")
        return raw_messages
    except Exception as e:
        _ = st.error(f"Lỗi tải tin nhắn thô: {e}")
        return []

def render_raw_message(message, key: str) -> None:
    """Render tin nhắn thô (đã mã hóa)."""
    is_user = message.role.value == "user"
    css_class = "user-message" if is_user else "assistant-message"
    role_name = "Bạn" if is_user else "AI"
    
    _ = st.markdown(f"""
    <div class="chat-message {css_class}">
        <div class="message-header">{role_name} • {message.created_at.strftime('%H:%M:%S')} • 🔐 ENCRYPTED</div>
        <div class="message-content" style="font-family: monospace; background-color: #f8f9fa; padding: 8px; border-radius: 4px;">
            {message.content}
        </div>
    </div>
    """, unsafe_allow_html=True)

def chat_tab():
    """Tab chat với tin nhắn đã giải mã."""
    if not st.session_state.current_session_id:
        st.info("📝 Chọn hoặc tạo phiên hội thoại ở thanh bên để bắt đầu!")
        return
    
    # Container cho tin nhắn
    messages_container = st.container()
    
    with messages_container:
        # Hiển thị tin nhắn đã giải mã
        if st.session_state.messages:
            for i, message in enumerate(st.session_state.messages):
                render_message(message, f"msg_{i}")
        else:
            st.info("💭 Chưa có tin nhắn nào. Hãy bắt đầu cuộc trò chuyện!")
    
    # Input chat
    st.markdown("---")
    
    with st.form("chat_form", clear_on_submit=True):
        col1, col2 = st.columns([6, 1])
        
        with col1:
            user_input = st.text_area(
                "Tin nhắn của bạn:",
                placeholder="Nhập tin nhắn...",
                height=100,
                label_visibility="collapsed"
            )
        
        with col2:
            st.write("")  # Spacer
            submit_button = st.form_submit_button("📤 Gửi", type="primary")
        
        # System instruction (tùy chọn)
        with st.expander("⚙️ Cài đặt nâng cao"):
            system_instruction = st.text_area(
                "Hướng dẫn hệ thống:",
                placeholder="Bạn là một trợ lý AI hữu ích...",
                height=60
            )
            
            col_temp, col_thinking = st.columns(2)
            with col_temp:
                temperature = st.slider("Temperature:", 0.0, 2.0, 1.0, 0.1)
            with col_thinking:
                thinking_budget = st.number_input("Thinking Budget:", 0, 10000, 0)
    
    # Xử lý submit
    if submit_button and user_input.strip():
        try:
            with st.spinner("🤔 AI đang suy nghĩ..."):
                # Gửi tin nhắn
                response = st.session_state.chatbot.chat(
                    session_id=st.session_state.current_session_id,
                    user_message=user_input.strip(),
                    system_instruction=system_instruction if system_instruction.strip() else None,
                    temperature=temperature,
                    thinking_budget=thinking_budget
                )
                
                # Reload tin nhắn (cả decoded và raw)
                st.session_state.messages = load_messages(
                    st.session_state.chatbot, 
                    st.session_state.current_session_id
                )
                st.session_state.raw_messages = load_raw_messages(
                    st.session_state.chatbot,
                    st.session_state.current_session_id
                )
                
                st.rerun()
                
        except Exception as e:
            st.error(f"❌ Lỗi khi gửi tin nhắn: {e}")

def raw_tab():
    """Tab hiển thị tin nhắn thô (đã mã hóa)."""
    if not st.session_state.current_session_id:
        st.info("📝 Chọn hoặc tạo phiên hội thoại ở thanh bên để bắt đầu!")
        return
    
    st.info("🔐 **Dữ liệu thô trong Database** - Tất cả tin nhắn được mã hóa bằng Vigenère Autokey")
    
    # Thêm nút refresh cho raw messages
    col1, col2, col3 = st.columns([1, 1, 4])
    with col1:
        if st.button("🔄 Làm mới", key="refresh_raw"):
            st.session_state.raw_messages = load_raw_messages(
                st.session_state.chatbot,
                st.session_state.current_session_id
            )
            st.rerun()
    
    with col2:
        if st.button("🔍 Phân tích", key="analyze_encryption"):
            if hasattr(st.session_state, 'raw_messages') and st.session_state.raw_messages:
                # Hiển thị thống kê mã hóa
                total_msgs = len(st.session_state.raw_messages)
                total_chars = sum(len(msg.content) for msg in st.session_state.raw_messages)
                st.info(f"📊 **Thống kê:** {total_msgs} tin nhắn, {total_chars} ký tự đã mã hóa")
    
    # Container cho tin nhắn thô
    if hasattr(st.session_state, 'raw_messages'):
        if st.session_state.raw_messages:
            for i, message in enumerate(st.session_state.raw_messages):
                render_raw_message(message, f"raw_msg_{i}")
        else:
            st.info("🔒 Chưa có dữ liệu mã hóa nào.")
    else:
        # Load raw messages lần đầu
        st.session_state.raw_messages = load_raw_messages(
            st.session_state.chatbot,
            st.session_state.current_session_id
        )
        if st.session_state.raw_messages:
            st.rerun()
        else:
            st.info("🔒 Chưa có dữ liệu mã hóa nào.")

def main_chat_interface():
    """Giao diện chat chính với tabs."""
    st.title("🔐 Encrypted Chatbot")
    
    if not st.session_state.chatbot:
        st.warning("⚠️ Vui lòng khởi tạo chatbot ở thanh bên trước!")
        st.info("""
        **Hướng dẫn:**
        1. Thiết lập biến môi trường `GOOGLE_GENAI_API_KEY`
        2. Nhập khóa mã hóa ở thanh bên
        3. Chọn chế độ autokey
        4. Nhấn "Khởi tạo Chatbot"
        5. Tạo phiên mới và bắt đầu chat!
        """)
        return
    
    if not st.session_state.current_session_id:
        st.info("📝 Chọn hoặc tạo phiên hội thoại ở thanh bên để bắt đầu!")
        return
    
    # Hiển thị thông tin phiên hiện tại
    current_session = None
    for session in st.session_state.sessions:
        if session.id == st.session_state.current_session_id:
            current_session = session
            break
    
    if current_session:
        st.info(f"**Phiên hiện tại:** {current_session.title} | **ID:** {current_session.id[:8]}...")
    
    # Tạo tabs
    tab1, tab2 = st.tabs(["💬 Chat (Đã giải mã)", "🔐 Raw (Trước khi giải mã)"])
    
    with tab1:
        chat_tab()
    
    with tab2:
        raw_tab()

def main():
    """Hàm main."""
    initialize_session_state()
    
    # Sidebar
    encryption_key, encryption_mode, db_path = sidebar_config()
    sidebar_sessions()
    
    # Main interface
    main_chat_interface()
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666; font-size: 0.8rem;">
        🔐 Encrypted Chatbot - Tất cả tin nhắn được mã hóa bằng Vigenère Autokey
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
