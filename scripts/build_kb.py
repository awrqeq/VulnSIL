# scripts/build_kb.py
import sys
import os
import json
import glob
import pickle
import logging
import numpy as np
import faiss
from tqdm import tqdm
from rank_bm25 import BM25Okapi

# 路径适配
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings
from vulnsil.database import get_db_session, engine, Base
from vulnsil.models import KnowledgeBase
from vulnsil.core.retrieval.vector_db_manager import EmbeddingModel
# [关键] 引入压缩器以实现数据对齐
from vulnsil.core.static_analysis.compressor import SemanticCompressor
from vulnsil.utils_log import setup_logging

setup_logging("build_kb")
log = logging.getLogger(__name__)


def parse_json_file(filepath: str):
    """解析 JSON 或 JSONL 文件"""
    records = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if content.startswith('['):
                try:
                    records = json.loads(content)
                except json.JSONDecodeError:
                    pass
            else:
                lines = content.split('\n')
                for line in lines:
                    if line.strip():
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
    except Exception as e:
        log.error(f"Read Error: {filepath} - {e}")
    return records


def print_summary_table(stats: dict):
    """打印统计报表"""
    print("\n" + "=" * 65)
    print(f" RAG IMPORT SUMMARY REPORT")
    print("=" * 65)
    print(f"{'DATASET FILE':<30} | {'IMPORTED (VULN)':<15} | {'SKIPPED':<15}")
    print("-" * 65)
    total_ok, total_skip = 0, 0
    for fname, info in stats.items():
        print(f"{fname:<30} | {info['added']:<15} | {info['skipped']:<15}")
        total_ok += info['added']
        total_skip += info['skipped']
    print("-" * 65)
    print(f"{'TOTAL':<30} | {total_ok:<15} | {total_skip:<15}")
    print("=" * 65 + "\n")


def import_rag_data_scan(db):
    """步骤 1: 扫描 RAG 目录并入库 (原始数据)"""
    rag_dir = os.path.join(settings.DATA_DIR, "data_RAG")
    if not os.path.exists(rag_dir):
        log.critical(f"RAG dir missing: {rag_dir}")
        return 0

    files = glob.glob(os.path.join(rag_dir, "*.json")) + glob.glob(os.path.join(rag_dir, "*.jsonl"))
    stats_report = {}

    log.info(f"Scanning {len(files)} files in {rag_dir}...")

    for filepath in files:
        filename = os.path.basename(filepath)
        records = parse_json_file(filepath)

        batch_buffer = []
        file_added_count = 0

        # 先获取当前文件已有的所有 OID，用于增量去重
        existing_oids = {r[0] for r in db.query(KnowledgeBase.original_id).filter(
            KnowledgeBase.source_dataset == filename).all()}

        for idx, item in enumerate(records):
            try:
                code = item.get('func') or item.get('code') or item.get('function')
                if not code: continue

                # 标签过滤 (仅漏洞)
                raw_label = item.get('target') if item.get('target') is not None else item.get('label')
                if raw_label is None: raw_label = item.get('vuln')
                try:
                    if int(raw_label) != 1: continue
                except:
                    continue

                # CWE 处理
                cwe_val = item.get('cwe_id')
                if not cwe_val or str(cwe_val).lower() in ['nan', 'null', 'none', '', '[]']:
                    cwe_val = "N/A"
                elif isinstance(cwe_val, list):
                    cwe_val = cwe_val[0] if cwe_val else "N/A"

                # [核心修复] 构造唯一 ID
                # 必须加入 idx，因为一个 commit_id 可能对应多行代码数据
                # 新格式: {filename}_{行号idx}_{commit_id前8位...}
                cid = item.get('commit_id') or item.get('id') or "unk"
                oid = f"{filename}_{idx}_{str(cid)[:32]}"

                # 内存级别查重，防止文件内部重复（虽不太可能，但为了稳妥）或者 DB 重复
                if oid in existing_oids:
                    continue

                kb = KnowledgeBase(
                    original_id=oid,
                    code=code,
                    label="VULNERABLE",
                    cwe_id=str(cwe_val),
                    source_dataset=filename
                )
                batch_buffer.append(kb)
                # 加入集合，防止批次内自我冲突
                existing_oids.add(oid)

            except Exception:
                continue

        # 批量入库
        if batch_buffer:
            try:
                batch_size = settings.KB_BUILD_BATCH_INSERT_SIZE
                for i in range(0, len(batch_buffer), batch_size):
                    chunk = batch_buffer[i:i + batch_size]
                    db.bulk_save_objects(chunk)
                    db.commit()  # 每一小批提交一次，降低内存压力

                file_added_count = len(batch_buffer)
                log.info(f"Processed {filename}: Added {file_added_count}")
            except Exception as e:
                db.rollback()
                log.error(f"Batch Insert Failed for {filename}: {e}")
                # 发生错误时返回0
                file_added_count = 0
        else:
            log.info(f"Processed {filename}: No new unique entries found.")

        stats_report[filename] = {"added": file_added_count, "skipped": len(records) - file_added_count}

    print_summary_table(stats_report)
    return sum(s['added'] for s in stats_report.values())


def build_indices(db):
    """
    步骤 2: 构建索引
    [核心改进]: 先对代码进行压缩，确保与推理阶段 (run_pipeline) 使用的输入一致
    """
    count = db.query(KnowledgeBase).count()
    if count == 0:
        log.warning("KnowledgeBase empty. Skipping index build.")
        return

    log.info(f"Building indices for {count} entries...")
    log.info("Loading Models (Encoder & Compressor)...")

    encoder = EmbeddingModel()  # Auto-device & normalization

    # 尝试初始化压缩器
    try:
        compressor = SemanticCompressor()
        log.info("Semantic Compressor loaded for alignment.")
    except Exception as e:
        log.error(f"Compressor init failed ({e}). Falling back to RAW code indexing (Quality Reduced).")
        compressor = None

    # 分页查询避免内存爆炸
    total_entries = db.query(KnowledgeBase.id).count()
    chunk_size = settings.KB_BUILD_CHUNK_SIZE

    vectors_list = []
    tokenized_corpus = []
    db_ids_list = []

    log.info("Generating Embeddings (Batched)...")

    for offset in range(0, total_entries, chunk_size):
        entries = db.query(KnowledgeBase).offset(offset).limit(chunk_size).all()
        if not entries: break

        for item in tqdm(entries, desc=f"Chunk {offset // chunk_size + 1}", leave=False):
            # 1. 语义压缩 (与 Inference 对齐)
            if compressor:
                try:
                    processed_code = compressor.compress(item.code, settings.MAX_CODE_TOKENS_INPUT)
                except:
                    processed_code = item.code
            else:
                processed_code = item.code

            # 2. Vector
            vec = encoder.encode(processed_code)
            vectors_list.append(vec)

            # 3. BM25 Tokenize (简单按空字符分割)
            tokenized_corpus.append(processed_code.split())

            # 4. Mapping
            db_ids_list.append(item.id)

    if not vectors_list:
        log.error("No vectors generated. Check data source.")
        return

    # FAISS Save (Inner Product + Normalized Vectors = Cosine Sim)
    log.info("Creating FAISS Index...")
    vectors_np = np.vstack(vectors_list).astype('float32')
    index = faiss.IndexFlatIP(vectors_np.shape[1])
    index.add(vectors_np)

    os.makedirs(os.path.dirname(settings.FAISS_INDEX_PATH), exist_ok=True)
    faiss.write_index(index, settings.FAISS_INDEX_PATH)
    log.info(f"Saved FAISS -> {settings.FAISS_INDEX_PATH}")

    # BM25 Save
    log.info("Creating BM25 Index...")
    bm25 = BM25Okapi(tokenized_corpus)
    with open(settings.BM25_INDEX_PATH, 'wb') as f:
        pickle.dump({'model': bm25, 'ids': db_ids_list}, f)
    log.info(f"Saved BM25 -> {settings.BM25_INDEX_PATH}")

    log.info("✅ Indexing Successfully Completed.")


if __name__ == "__main__":
    try:
        Base.metadata.create_all(bind=engine)
        with get_db_session() as sess:
            # Step 1
            import_rag_data_scan(sess)
            # Step 2
            build_indices(sess)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        log.critical(f"Fatal: {e}", exc_info=True)