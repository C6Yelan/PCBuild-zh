# backend/api/deps.py
from collections.abc import Generator

from sqlalchemy.orm import Session

from backend.db import SessionLocal


def get_db() -> Generator[Session, None, None]:
    """
    提供 FastAPI Depends 使用的資料庫 Session。

    使用方式範例：
        from fastapi import Depends
        from sqlalchemy.orm import Session
        from backend.api.deps import get_db

        def some_endpoint(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
