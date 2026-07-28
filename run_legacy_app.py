#!/usr/bin/env python3
"""
Script khởi động Streamlit app cho Encrypted Chatbot.

Sử dụng:
    python run_app.py
    
hoặc:
    streamlit run src/ui/streamlit_app.py
"""

import subprocess
import sys
import os

def _enforce_lab_only() -> None:
    """Refuse to launch the insecure legacy lab outside an explicitly enabled lab env.

    The legacy Streamlit/Vigenère app uses homemade crypto and unsafe HTML rendering.
    It must never run in production or staging (see the security posture assessment).
    """
    environment = os.getenv("APP_ENV", "development").strip().lower()
    if environment in {"production", "staging"}:
        print(f"⛔ Từ chối chạy legacy lab trong môi trường '{environment}'.")
        sys.exit(2)
    if os.getenv("LEGACY_LAB_ENABLED", "").strip().lower() not in {"1", "true", "yes", "on"}:
        print(
            "⛔ Legacy lab bị tắt mặc định. Chỉ bật trong môi trường lab cô lập bằng "
            "LEGACY_LAB_ENABLED=true."
        )
        sys.exit(2)


def main():
    """Chạy Streamlit app."""
    _enforce_lab_only()
    # Đảm bảo chúng ta ở thư mục root của project
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # Đường dẫn tới file Streamlit app
    app_path = os.path.join("src", "ui", "streamlit_app.py")
    
    if not os.path.exists(app_path):
        print(f"❌ Không tìm thấy file: {app_path}")
        sys.exit(1)
    
    print("🚀 Đang khởi động Encrypted Chatbot...")
    print(f"📁 Thư mục làm việc: {script_dir}")
    print(f"📄 File app: {app_path}")
    print("🌐 Streamlit sẽ mở tại: http://localhost:8501")
    print("-" * 50)
    
    try:
        # Chạy streamlit
        _ = subprocess.run([
            sys.executable, "-m", "streamlit", "run", app_path,
            "--server.address", "0.0.0.0",
            "--server.port", "8501",
            "--server.headless", "false"
        ], check=True)
    except KeyboardInterrupt:
        print("\n👋 Đã dừng ứng dụng!")
    except subprocess.CalledProcessError as e:
        print(f"❌ Lỗi chạy Streamlit: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print("❌ Không tìm thấy Streamlit. Hãy cài đặt bằng: pip install streamlit")
        sys.exit(1)

if __name__ == "__main__":
    main()
