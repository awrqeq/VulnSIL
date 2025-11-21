# vulnsil/utils_log.py
import logging
import sys
import os
from datetime import datetime
from config import settings

def setup_logging(log_name: str = "vulnsil"):
    """
    配置全局日志：同时输出到 控制台 和 文件 (results/logs/xxx.log)
    """
    # 1. 准备目录
    log_dir = settings.LOG_DIR
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    # 2. 生成带时间戳的文件名
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"{log_name}_{timestamp}.log")

    # 3. 获取根日志记录器 (Root Logger)
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # 4. 清除已有的 handler (防止重复打印，或者防止被 transformers 等库覆盖)
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    # 5. 定义格式
    formatter = logging.Formatter(
        fmt='%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # 6. 添加文件处理器 (FileHandler)
    file_handler = logging.FileHandler(log_file, encoding='utf-8', mode='w')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)

    # 7. 添加控制台处理器 (StreamHandler)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    root_logger.addHandler(console_handler)

    # 8. 屏蔽部分啰嗦的第三方库
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("filelock").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)

    # 记录启动信息
    root_logger.info(f"Logging initialized. Writing to: {log_file}")

    return root_logger