# vulnsil/core/retrieval/hybrid_search.py
import pickle
import numpy as np
import logging
import os
import faiss
from typing import List, Dict

from config import settings
from vulnsil.database import get_db_session
from vulnsil.models import KnowledgeBase
from vulnsil.schemas import KnowledgeBaseEntry
from vulnsil.core.retrieval.vector_db_manager import EmbeddingModel

logger = logging.getLogger(__name__)

class HybridRetriever:
    def __init__(self):
        self.embedding_model = None
        self.faiss_index = None
        self.bm25_model = None
        self.ids_map = []
        self._load_resources()

    def _load_resources(self):
        try:
            self.embedding_model = EmbeddingModel()

            if os.path.exists(settings.FAISS_INDEX_PATH):
                self.faiss_index = faiss.read_index(settings.FAISS_INDEX_PATH)
            else:
                logger.warning("FAISS index missing.")

            if os.path.exists(settings.BM25_INDEX_PATH):
                with open(settings.BM25_INDEX_PATH, 'rb') as f:
                    data = pickle.load(f)
                    self.bm25_model = data['model']
                    self.ids_map = data['ids']
            else:
                logger.warning("BM25 index missing.")

        except Exception as e:
            logger.error(f"Retriever Init Error: {e}")

    def _rrf_fusion(self, rank_lists: List[List[int]], k: int = 60) -> Dict[int, float]:
        rrf_map = {}
        for rank_list in rank_lists:
            for rank, doc_id in enumerate(rank_list):
                if doc_id not in rrf_map:
                    rrf_map[doc_id] = 0.0
                rrf_map[doc_id] += 1.0 / (k + rank + 1)
        return rrf_map

    def search(self, code_query: str, top_k: int = 5) -> List[KnowledgeBaseEntry]:
        if not self.faiss_index or not self.embedding_model:
            return []

        candidate_k = top_k * 4

        # 1. Vector Search
        query_vec = self.embedding_model.encode(code_query).reshape(1, -1)
        _, I = self.faiss_index.search(query_vec, candidate_k)

        vector_ids = []
        # FAISS可能返回-1表示不足
        if I.size > 0:
            for idx in I[0]:
                if idx != -1 and 0 <= idx < len(self.ids_map):
                    vector_ids.append(self.ids_map[idx])

        # 2. Sparse Search
        tokens = code_query.split()
        if not tokens: tokens = ["void"] # fallback

        scores = self.bm25_model.get_scores(tokens)
        # numpy argsort is ascending, take reverse
        top_n_idx = np.argsort(scores)[::-1][:candidate_k]

        bm25_ids = []
        for idx in top_n_idx:
            if 0 <= idx < len(self.ids_map):
                bm25_ids.append(self.ids_map[idx])

        # 3. Fusion
        fused = self._rrf_fusion([vector_ids, bm25_ids])
        sorted_ids = sorted(fused.keys(), key=lambda x: fused[x], reverse=True)[:top_k]

        results = []
        if sorted_ids:
            with get_db_session() as db:
                # [核心修复] 必须 Select 出来 cwe_id 字段
                rows = db.query(KnowledgeBase).filter(KnowledgeBase.id.in_(sorted_ids)).all()
                row_map = {r.id: r for r in rows}

                for rid in sorted_ids:
                    if rid in row_map:
                        rec = row_map[rid]
                        entry = KnowledgeBaseEntry(
                            id=rec.id,
                            original_id=rec.original_id,
                            code=rec.code,
                            label=rec.label,
                            # [修复点] 这里正确赋值给 Pydantic 模型
                            cwe_id=rec.cwe_id if rec.cwe_id else "N/A",
                            similarity_score=fused[rid]
                        )
                        results.append(entry)
        return results