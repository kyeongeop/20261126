"""根目录入口垫片。

支持以下任一启动方式：
    python main.py
    uvicorn main:app --reload
    uvicorn app.main:app --reload
"""

import uvicorn

from app.main import app, create_app

__all__ = ["app", "create_app"]


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
