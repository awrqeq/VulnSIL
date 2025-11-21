# vulnsil/database.py
import logging
from contextlib import contextmanager
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session, declarative_base
from config import settings

log = logging.getLogger(__name__)

# 1. 配置引擎参数
engine_args = {}
if settings.DATABASE_URI.startswith("sqlite"):
    # SQLite 特定优化
    engine_args["connect_args"] = {
        "check_same_thread": False,
        "timeout": 30  # [优化] 默认是5秒，增加到30秒，给予线程更多等待锁释放的时间
    }

engine = create_engine(
    settings.DATABASE_URI,
    pool_size=30,
    max_overflow=40,
    **engine_args
)

# [核心优化] 开启 SQLite WAL 模式 (Write-Ahead Logging)
# 这允许多个读取者和一个写入者同时操作，极大减少 "database is locked" 的概率
if settings.DATABASE_URI.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

# 2. 创建会话工厂
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
ScopedSession = scoped_session(SessionLocal)

# 3. 声明基类
Base = declarative_base()

def init_db():
    """初始化表结构"""
    Base.metadata.create_all(bind=engine)
    log.info("Database initialized/verified (WAL Mode enabled).")

@contextmanager
def get_db_session():
    session = ScopedSession()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        # 捕获 operational error 并记录，但不一定要在这里炸掉整个pipeline，留给上层处理
        if "locked" in str(e):
            log.error(f"DB Locked: {e} (Check for suspended processes)")
        else:
            log.error(f"DB Session Error: {e}")
        raise
    finally:
        session.close()
        ScopedSession.remove()