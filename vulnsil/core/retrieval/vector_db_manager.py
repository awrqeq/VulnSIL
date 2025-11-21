# vulnsil/core/retrieval/vector_db_manager.py
import numpy as np
import torch
import logging
import threading
from transformers import AutoTokenizer, AutoModel
from config import settings

log = logging.getLogger(__name__)


class EmbeddingModel:
    """
    CodeBERT Embedding (CPU-Optimized High Throughput Version).
    针对 GPU 显存爆满环境的特别优化：
    强制使用 CPU 进行向量计算。因为在 48 核服务器上，CPU 并行跑 BERT-base 的吞吐量
    远高于在一个爆满的 GPU 上排队。
    """

    def __init__(self):
        self.model_path = settings.EMBEDDING_MODEL_PATH

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            log.info("✅ Tokenizer loaded.")
        except Exception as e:
            log.critical(f"Tokenizer Load Failed: {e}")
            raise

        # [关键策略]: 强制使用 CPU，放弃纠结显存
        self.device = torch.device("cpu")
        log.info("⚠️ GPU 0 is congested. Forcing CodeBERT to run on CPU for stable throughput.")

        self.model = AutoModel.from_pretrained(self.model_path).to(self.device)
        self.model.eval()

        # 这里的锁只保护模型前向传播，防止 torch 内部多线程打架
        # 在 CPU 模式下，这种争抢通常很小
        self.lock = threading.Lock()

    @torch.no_grad()
    def encode(self, text: str) -> np.ndarray:
        if not isinstance(text, str) or not text.strip():
            return np.zeros(768, dtype='float32')

        # 虽然 Python 有 GIL，但 Torch 的底层矩阵运算会释放 GIL
        # 因此多线程同时调这个 encode 是能吃到多核 CPU 红利的
        with self.lock:
            try:
                inputs = self.tokenizer(text, return_tensors='pt', max_length=512, truncation=True, padding=True)
                inputs = {k: v.to(self.device) for k, v in inputs.items()}

                outputs = self.model(**inputs)
                # 这里的切片操作在 CPU 上很快
                embedding = outputs.last_hidden_state[:, 0, :].numpy()[0].astype('float32')

                norm = np.linalg.norm(embedding)
                if norm > 1e-10:
                    embedding = embedding / norm

                return embedding

            except Exception as e:
                log.error(f"Embedding fail: {e}")
                return np.zeros(768, dtype='float32')