# config.py
import os
import logging
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT_DIR = os.path.abspath(os.path.dirname(__file__))


class Settings(BaseSettings):
    # --- 基础路径 ---
    DATA_DIR: str = os.path.join(PROJECT_ROOT_DIR, 'data')
    RESULTS_DIR: str = os.path.join(PROJECT_ROOT_DIR, 'results')
    LOG_DIR: str = os.path.join(RESULTS_DIR, 'logs')
    DB_DIR: str = os.path.join(RESULTS_DIR, 'database')

    # RAG资源
    FAISS_INDEX_PATH: str = os.path.join(RESULTS_DIR, 'faiss_index', 'kb.faiss')
    BM25_INDEX_PATH: str = os.path.join(RESULTS_DIR, 'faiss_index', 'kb.bm25')

    # 资源文件
    RESOURCE_DIR: str = os.path.join(PROJECT_ROOT_DIR, 'vulnsil', 'resources')
    JOERN_SCRIPT_PATH: str = os.path.join(RESOURCE_DIR, 'query.sc')

    # 数据库
    DATABASE_URI: str = f"sqlite:///{os.path.join(DB_DIR, 'vulnsil.db')}"

    # 模型路径
    CONFIDENCE_MODEL_PATH: str = os.path.join(RESULTS_DIR, 'confidence', 'lgb_model.joblib')

    # --- 工具配置 ---
    LLM_API_URL: str = "http://localhost:8000/v1/chat/completions"
    LLM_MODEL_NAME: str = "Llama-3.1-8B-Instruct"

    EMBEDDING_MODEL_PATH: str = "/home/daiwenju/codebert-base"

    # [关键修正]: 适配您的 joern4.4.3 环境
    # 1. Joern 主程序路径 (用于运行 scala 脚本)
    JOERN_CLI_PATH: str = "/home/daiwenju/joern4.4.3/joern-cli/joern"

    # 2. C/C++ CPG生成器路径 (替代 joern-parse)
    # Joern v4 中，处理 C/C++ 使用 c2cpg.sh
    JOERN_PARSE_PATH: str = "/home/daiwenju/joern4.4.3/joern-cli/c2cpg.sh"

    # --- 参数 ---
    LLM_MAX_MODEL_LEN: int = 14480
    MAX_CODE_TOKENS_INPUT: int = 12000
    COMPRESSION_TRIGGER_LEN: int = 12000
    RAG_TOP_K: int = 5
    CONFIDENCE_THRESHOLD: float = 0.75

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

# 自动创建目录
for path in [settings.RESULTS_DIR, settings.LOG_DIR, settings.DB_DIR,
             os.path.dirname(settings.FAISS_INDEX_PATH),
             os.path.dirname(settings.CONFIDENCE_MODEL_PATH)]:
    os.makedirs(path, exist_ok=True)