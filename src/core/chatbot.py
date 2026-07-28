from __future__ import annotations

from typing import Literal

from database.database import Database
from database.models import MessageCreate, Role, Session, Message
from core.ai_core.gemini_ai import GeminiClient
from core.crypto import vigenere_autokey_encrypt, vigenere_autokey_decrypt

from core.ai_core.memory import Memory

class EncryptedChatbot:
    """
    Chatbot với khả năng mã hóa tin nhắn tự động.
    
    Tất cả tin nhắn được mã hóa bằng Vigenère Autokey trước khi lưu vào database
    và được giải mã trước khi gửi cho AI model.
    
    Workflow:
    1. Người dùng gửi tin nhắn (plaintext)
    2. Mã hóa tin nhắn và lưu vào database
    3. Đọc lịch sử từ database và giải mã 
    4. Gửi lịch sử đã giải mã cho Gemini AI
    5. Mã hóa phản hồi của AI và lưu vào database
    """
    
    def __init__(
        self,
        db: Database,
        gemini_client: GeminiClient,
        encryption_key: str,
        encryption_mode: Literal["plaintext", "ciphertext"] = "plaintext"
    ):
        """
        Args:
            db: Database instance để lưu trữ tin nhắn đã mã hóa
            gemini_client: GeminiClient để tương tác với Gemini AI  
            encryption_key: Khóa mã hóa cho Vigenère Autokey
            encryption_mode: Chế độ autokey ("plaintext" hoặc "ciphertext")
        """
        self.db: Database = db
        self.gemini: GeminiClient = gemini_client
        self.memory: Memory = Memory(db)
        self.encryption_key: str = encryption_key
        self.encryption_mode: Literal["plaintext", "ciphertext"] = encryption_mode
    
    def _encrypt_content(self, content: str) -> str:
        """Mã hóa nội dung tin nhắn."""
        try:
            return vigenere_autokey_encrypt(
                content, 
                self.encryption_key, 
                mode=self.encryption_mode
            )
        except Exception as e:
            raise ValueError(f"Lỗi mã hóa: {e}")
    
    def _decrypt_content(self, encrypted_content: str) -> str:
        """Giải mã nội dung tin nhắn."""
        try:
            return vigenere_autokey_decrypt(
                encrypted_content,
                self.encryption_key,
                mode=self.encryption_mode
            )
        except Exception as e:
            raise ValueError(f"Lỗi giải mã: {e}")
    
    def _decrypt_message(self, message: Message) -> Message:
        """Giải mã một tin nhắn."""
        decrypted_content = self._decrypt_content(message.content)
        # Tạo message mới với nội dung đã giải mã
        return Message(
            id=message.id,
            session_id=message.session_id,
            role=message.role,
            content=decrypted_content,
            meta=message.meta,
            created_at=message.created_at
        )
    
    def _decrypt_messages(self, messages: list[Message]) -> list[Message]:
        """Giải mã danh sách tin nhắn."""
        return [self._decrypt_message(msg) for msg in messages]
    
    def start_session(self, title: str | None = None) -> Session:
        """Tạo phiên hội thoại mới."""
        return self.memory.start_session(title)
    
    def add_user_message(
        self, 
        session_id: str, 
        content: str, 
        meta: dict[str, object] | None = None
    ) -> Message:
        """
        Thêm tin nhắn người dùng (mã hóa trước khi lưu).
        
        Args:
            session_id: ID phiên hội thoại
            content: Nội dung tin nhắn (plaintext)
            meta: Metadata bổ sung
            
        Returns:
            Message đã được lưu (với nội dung đã mã hóa)
        """
        encrypted_content = self._encrypt_content(content)
        return self.db.insert_message(
            MessageCreate(
                session_id=session_id,
                role=Role.user,
                content=encrypted_content,
                meta=meta or {}
            )
        )
    
    def add_assistant_message(
        self,
        session_id: str,
        content: str, 
        meta: dict[str, object] | None = None
    ) -> Message:
        """
        Thêm tin nhắn trợ lý (mã hóa trước khi lưu).
        
        Args:
            session_id: ID phiên hội thoại
            content: Nội dung tin nhắn (plaintext)
            meta: Metadata bổ sung
            
        Returns:
            Message đã được lưu (với nội dung đã mã hóa)
        """
        encrypted_content = self._encrypt_content(content)
        return self.db.insert_message(
            MessageCreate(
                session_id=session_id,
                role=Role.assistant,
                content=encrypted_content,
                meta=meta or {}
            )
        )
    
    def get_decrypted_history(
        self, 
        session_id: str, 
        limit: int | None = None
    ) -> list[Message]:
        """
        Lấy lịch sử hội thoại đã giải mã.
        
        Args:
            session_id: ID phiên hội thoại
            limit: Giới hạn số tin nhắn
            
        Returns:
            Danh sách tin nhắn đã giải mã
        """
        encrypted_messages = self.db.fetch_messages(session_id, limit=limit, order="asc")
        return self._decrypt_messages(encrypted_messages)
    
    def get_chat_history_for_ai(
        self, 
        session_id: str, 
        limit: int | None = None
    ) -> list[dict[str, object]]:
        """
        Lấy lịch sử hội thoại định dạng cho AI (đã giải mã).
        
        Args:
            session_id: ID phiên hội thoại  
            limit: Giới hạn số tin nhắn
            
        Returns:
            Danh sách dict {role, content, meta} đã giải mã
        """
        decrypted_messages = self.get_decrypted_history(session_id, limit)
        return [
            {
                "role": msg.role.value,
                "content": msg.content,
                "meta": msg.meta
            }
            for msg in decrypted_messages
        ]
    
    def chat(
        self,
        session_id: str,
        user_message: str,
        system_instruction: str | None = None,
        temperature: float | None = None,
        thinking_budget: int | None = 0,
        **gemini_kwargs
    ) -> str:
        """
        Thực hiện một lượt hội thoại hoàn chỉnh.
        
        Args:
            session_id: ID phiên hội thoại
            user_message: Tin nhắn người dùng (plaintext)
            system_instruction: Hướng dẫn hệ thống
            temperature: Nhiệt độ sampling
            thinking_budget: Ngân sách thinking
            **gemini_kwargs: Các tham số bổ sung cho Gemini
            
        Returns:
            Phản hồi của AI (plaintext)
        """
        # 1. Lưu tin nhắn người dùng (đã mã hóa)
        _  = self.add_user_message(session_id, user_message)

        # 2. Lấy lịch sử hội thoại (đã giải mã)
        chat_history = self.get_chat_history_for_ai(session_id)
        
        # 3. Chuẩn bị nội dung cho Gemini
        # Nếu có nhiều tin nhắn, ghép chúng lại hoặc chỉ lấy tin nhắn cuối
        if chat_history:
            # Lấy tin nhắn cuối cùng (của user)
            last_message = chat_history[-1]
            user_content = last_message["content"]
            
            # Nếu có lịch sử, có thể thêm context
            if len(chat_history) > 1:
                context_messages = chat_history[:-1]
                context = "\n".join([
                    f"{msg['role']}: {msg['content']}"
                    for msg in context_messages[-5:]  # Lấy 5 tin nhắn gần nhất làm context
                ])
                user_content = f"Lịch sử hội thoại:\n{context}\n\nTin nhắn hiện tại: {user_content}"
        else:
            user_content = user_message
        
        # 4. Gọi Gemini AI
        try:
            ai_response = self.gemini.generate(
                user_content=user_content,
                system_instruction=system_instruction,
                temperature=temperature,
                thinking_budget=thinking_budget,
                **gemini_kwargs
            )
        except Exception as e:
            ai_response = f"Lỗi khi gọi AI: {e}"
        
        # 5. Lưu phản hồi AI (đã mã hóa)
        _ = self.add_assistant_message(session_id, ai_response)
        
        return ai_response
    
    def get_session_info(self, session_id: str) -> Session | None:
        """Lấy thông tin phiên hội thoại."""
        return self.db.get_session(session_id)
    
    def list_sessions(self, limit: int = 20, offset: int = 0) -> list[Session]:
        """Liệt kê các phiên hội thoại."""
        return self.db.list_sessions(limit, offset)
    
    def delete_session(self, session_id: str) -> None:
        """Xóa phiên hội thoại."""
        self.db.delete_session(session_id)
    
    def clear_session_messages(self, session_id: str) -> int:
        """Xóa tất cả tin nhắn trong phiên."""
        return self.db.clear_messages_by_session(session_id)


# Factory function để tạo chatbot dễ dàng
def create_encrypted_chatbot(
    db_path: str = "encrypted_chat.db",
    encryption_key: str = "DEFAULTKEY",
    encryption_mode: Literal['plaintext', 'ciphertext'] = "plaintext",
    gemini_api_key: str | None = None,
    gemini_model: str = "gemini-2.5-flash-lite"
) -> EncryptedChatbot:
    """
    Tạo instance EncryptedChatbot với cấu hình mặc định.
    
    Args:
        db_path: Đường dẫn file database
        encryption_key: Khóa mã hóa
        encryption_mode: Chế độ autokey
        gemini_api_key: API key Gemini (None = đọc từ env)
        gemini_model: Tên model Gemini
        
    Returns:
        EncryptedChatbot instance
    """
    db = Database(db_path)
    gemini = GeminiClient(api_key=gemini_api_key, model=gemini_model)
    
    return EncryptedChatbot(
        db=db,
        gemini_client=gemini,
        encryption_key=encryption_key,
        encryption_mode=encryption_mode
    )


if __name__ == "__main__":
    # Demo sử dụng
    import os
    from dotenv import load_dotenv
    
    load_dotenv()
    
    # Tạo chatbot
    chatbot = create_encrypted_chatbot(
        encryption_key="MYSECRETKEY",
        encryption_mode="plaintext"
    )
    
    # Tạo phiên mới
    session = chatbot.start_session("Demo Encrypted Chat")
    print(f"Tạo phiên: {session.id}")
    
    # Chat
    response = chatbot.chat(
        session_id=session.id,
        user_message="Xin chào! Bạn có thể giúp tôi không?",
    )
    
    print(f"AI: {response}")
    
    # Xem lịch sử đã giải mã
    history = chatbot.get_decrypted_history(session.id)
    print("\nLịch sử hội thoại (đã giải mã):")
    for msg in history:
        print(f"{msg.role.value}: {msg.content}")
