# backend/api/debug.py
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.api.deps import get_db

router = APIRouter(tags=["debug"])


@router.get("/debug/db")
def debug_db(db: Session = Depends(get_db)):
    """
    測試資料庫是否可連線。
    使用 SQLAlchemy 的 select，而不是手寫 SQL 字串。
    """
    result = db.execute(select(1)).scalar_one()
    return {"db_ok": result == 1}
