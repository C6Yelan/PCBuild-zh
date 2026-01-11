# backend/core/init_db.py
from backend.core.database import engine
from backend.models.base import Base


def init_db_schema() -> None:
    """
    明確初始化 DB schema。
    注意：必須先 import 所有 models，讓 Table 都註冊進 Base.metadata，
    否則 create_all 可能漏建表。
    """
    import backend.models  # noqa: F401  # 只為了註冊 metadata

    Base.metadata.create_all(bind=engine)
