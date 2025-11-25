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

    # LLM 采样参数
    LLM_TEMPERATURE: float = 0.1
    LLM_MAX_TOKENS: int = 2048
    LLM_REPETITION_PENALTY: float = 1.1
    LLM_TIMEOUT: int = 240

    EMBEDDING_MODEL_PATH: str = "/home/daiwenju/codebert-base"

    # [关键修正]: 适配您的 joern4.4.3 环境
    # 1. Joern 主程序路径 (用于运行 scala 脚本)
    JOERN_CLI_PATH: str = "/home/daiwenju/joern4.4.3/joern-cli/joern"

    # 2. C/C++ CPG生成器路径 (替代 joern-parse)
    # Joern v4 中，处理 C/C++ 使用 c2cpg.sh
    JOERN_PARSE_PATH: str = "/home/daiwenju/joern4.4.3/joern-cli/c2cpg.sh"

    # Joern JVM 参数
    JOERN_JAVA_OPTS: str = "-Xms512m -Xmx4g -server"
    JOERN_JAVA_OPTIONS: str = "-Xms512m -Xmx4g -XX:+UseSerialGC"

    # --- 参数 ---
    LLM_MAX_MODEL_LEN: int = 14480
    MAX_CODE_TOKENS_INPUT: int = 12000
    COMPRESSION_TRIGGER_LEN: int = 12000
    RAG_TOP_K: int = 5
    RAG_CANDIDATE_PADDING: int = 5
    CONFIDENCE_THRESHOLD: float = 0.75

    # 批处理/并发参数
    STATIC_BATCH_SIZE: int = 500
    STATIC_PARSE_TIMEOUT: int = 120
    STATIC_QUERY_TIMEOUT: int = 120
    STATIC_TMP_DIR: str = "/dev/shm"
    INFERENCE_THREAD_COUNT: int = 24

    # 检索索引参数
    RETRIEVAL_RRF_K: int = 60
    RETRIEVAL_VECTOR_CANDIDATE_MULTIPLIER: int = 4
    KB_BUILD_CHUNK_SIZE: int = 5000
    KB_BUILD_BATCH_INSERT_SIZE: int = 1000

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

# 自动创建目录
for path in [settings.RESULTS_DIR, settings.LOG_DIR, settings.DB_DIR,
             os.path.dirname(settings.FAISS_INDEX_PATH),
             os.path.dirname(settings.CONFIDENCE_MODEL_PATH)]:
    os.makedirs(path, exist_ok=True)
