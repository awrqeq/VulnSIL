# run_pipeline.py
import typer
import logging
import joblib
import os
import gc
import torch
import threading
import numpy as np
# 使用 as_completed 做并发控制
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from sqlalchemy.exc import SQLAlchemyError

from vulnsil.database import get_db_session
from vulnsil.models import Vulnerability, AnalysisResultRecord
from vulnsil.core.static_analysis.engine import DualEngineAnalyzer
from vulnsil.core.retrieval.hybrid_search import HybridRetriever
from vulnsil.core.llm.vllm_client import VLLMClient
from vulnsil.core.llm.prompts import PromptManager
from vulnsil.utils_log import setup_logging
from config import settings

app = typer.Typer()
logger = setup_logging("pipeline")

# --- Config: 批处理模式优化参数 ---
# 推理阶段并发数 (Static已在主线程批量完成)
FIXED_THREAD_COUNT = 24
# 静态分析批次大小 (一次启动分析 500-1000 个最佳)
BATCH_SIZE_STATIC = 500

STOP_EVENT = threading.Event()

STATIC_ENGINE = DualEngineAnalyzer()
RETRIEVER = HybridRetriever()
LLM_CLIENT = VLLMClient()

CALIBRATOR = None
if os.path.exists(settings.CONFIDENCE_MODEL_PATH):
    try:
        CALIBRATOR = joblib.load(settings.CONFIDENCE_MODEL_PATH)
        logger.info(f"Calibration Model Loaded")
    except:
        pass
else:
    logger.info("Collection Mode (No Calibrator)")


def manual_gc():
    gc.collect()
    if torch.cuda.is_available(): torch.cuda.empty_cache()


def process_inference_task(task: dict, static_feats: dict):
    """
    第二阶段: 独立的推理任务
    RAG -> LLM -> Feature Engineering -> DB Save
    """
    if STOP_EVENT.is_set(): return "Stopped"

    try:
        vuln_id = task['id']
        # 注意：Static 已经在 batch 中可能做过 compress，这里拿原始 code 给 RAG/LLM 即可
        # (PromptManager 内部会处理长度截断)
        safe_code = task['code']

        # Generate Description for Prompt
        if static_feats['has_data_flow']:
            flow_desc = "YES (Critical Data Flow Detected)"
        elif not static_feats.get('success', False):
            flow_desc = "UNKNOWN (Parsing Partial)"
        else:
            flow_desc = "NO"

        # 1. RAG
        raw_rag = RETRIEVER.search(safe_code, top_k=settings.RAG_TOP_K + 5)
        final_rag = []
        curr_k = 0
        for e in raw_rag:
            if curr_k >= settings.RAG_TOP_K: break
            if str(e.original_id) not in task['name'] and e.similarity_score < 0.999:
                final_rag.append(e)
                curr_k += 1

        # 2. LLM
        prompt = PromptManager.build_prompt(safe_code, final_rag, static_feats, flow_desc)
        full_prompt = f"System: {PromptManager.SYSTEM_PROMPT}\nUser: {prompt}"
        res, nat_conf = LLM_CLIENT.generate(full_prompt)

        # 3. Feat & Calib
        f_flow = 1 if static_feats['has_data_flow'] else 0
        f_comp = float(static_feats.get('complexity', 0))
        f_api = float(len(static_feats.get('apis', [])))
        f_log_len = np.log1p(len(safe_code))
        f_compr = 1 if len(safe_code) > settings.COMPRESSION_TRIGGER_LEN else 0

        sims = [e.similarity_score for e in final_rag]
        f_rag_stats = [float(np.mean(sims)) if sims else 0.0,
                       float(np.max(sims)) if sims else 0.0,
                       float(np.var(sims)) if sims else 0.0]

        llm_vuln = 1 if (res and res.decision.upper() == "VULNERABLE") else 0
        f_disagree = 1 if (f_flow != llm_vuln) else 0
        f_spec = 1 if (f_flow == 1 and llm_vuln == 0) else 0

        final_conf = nat_conf
        if CALIBRATOR:
            try:
                vec = np.array([[nat_conf, f_flow, f_comp, f_api, f_log_len, f_compr,
                                 *f_rag_stats, float(f_disagree), float(f_spec)]])
                final_conf = float(CALIBRATOR.predict_proba(vec)[0][1])
            except:
                pass

        # 4. Save
        with get_db_session() as db:
            v = db.get(Vulnerability, vuln_id)
            if v:
                db.query(AnalysisResultRecord).filter_by(vuln_id=v.id).delete()
                v.status = "Success" if res else "Failed"

                if res:
                    rec = AnalysisResultRecord(
                        vuln_id=v.id, raw_json=res.model_dump_json(),
                        final_decision=res.decision.value, cwe_id=res.cwe_id,
                        native_confidence=nat_conf, calibrated_confidence=final_conf,
                        static_has_flow=bool(f_flow), static_complexity=int(f_comp),
                        feat_static_apis_count=int(f_api), feat_code_len=len(safe_code),
                        feat_is_compressed=bool(f_compr), feat_rag_agreement=1.0,
                        feature_rag_similarity=f_rag_stats[0], feat_rag_top1_sim=f_rag_stats[1],
                        feat_rag_sim_variance=f_rag_stats[2],
                        feat_conflict_disagreement=f_disagree,
                        feat_conflict_static_yes_llm_no=f_spec
                    )
                    db.add(rec)

        return "Success" if res else "Failed"

    except Exception as e:
        logger.error(f"Inf fail {task['id']}: {e}")
        return "Failed"


def run_batched_pipeline(task_ids):
    # 拆分大批次
    total_len = len(task_ids)
    batches = [task_ids[i:i + BATCH_SIZE_STATIC] for i in range(0, total_len, BATCH_SIZE_STATIC)]

    logger.info(f"🚀 Pipeline Start: {total_len} tasks | {len(batches)} Batches | Mode: Batch-Static -> Async-Infer")

    with tqdm(total=total_len, desc="Processing") as pbar:
        for chunk_ids in batches:
            if STOP_EVENT.is_set(): break

            # 1. 加载数据
            tasks = []
            try:
                with get_db_session() as db:
                    rows = db.query(Vulnerability).filter(Vulnerability.id.in_(chunk_ids)).all()
                    for r in rows:
                        tasks.append({
                            "id": r.id, "name": r.name, "code": r.code,
                            "cwe_id": r.cwe_id
                        })
            except Exception:
                continue  # DB error skip batch

            if not tasks: continue

            # 2. [Batch Static] 这一步是阻塞的，但非常快
            # pbar.set_description("Static Analysis...")
            static_results_map = STATIC_ENGINE.analyze_batch(tasks)

            # 3. [Concurrent Inference]
            # pbar.set_description("LLM Inference...")
            try:
                with ThreadPoolExecutor(max_workers=FIXED_THREAD_COUNT) as ex:
                    futures = []
                    for t in tasks:
                        if STOP_EVENT.is_set(): break
                        # 获取特征 (一定有，因为 map 初始化过默认值)
                        feat = static_results_map.get(t['id'])
                        futures.append(ex.submit(process_inference_task, t, feat))

                    for f in as_completed(futures):
                        if STOP_EVENT.is_set(): break
                        f.result()
                        pbar.update(1)
            except KeyboardInterrupt:
                raise

            # 4. GC
            manual_gc()


@app.command()
def run(split: str = typer.Option(..., help="Dataset split prefix"), limit: int = -1):
    tids = []
    with get_db_session() as db:
        q = db.query(Vulnerability.id).filter(
            Vulnerability.name.like(f"{split}%"),
            Vulnerability.status.in_(["Pending", "Failed"])
        )
        if limit > 0: q = q.limit(limit)
        tids = [r[0] for r in q.all()]

    if not tids:
        print("No tasks found.")
        return

    try:
        run_batched_pipeline(tids)
    except KeyboardInterrupt:
        STOP_EVENT.set()
        print("\nUser Stopped.")

    # Final Report (Only prints required metrics)
    try:
        s_cnt, f_cnt = 0, 0
        with get_db_session() as db:
            res = db.query(Vulnerability.status).filter(Vulnerability.id.in_(tids)).all()
            stats = [r[0] for r in res]
            s_cnt = stats.count("Success")
            f_cnt = stats.count("Failed")

        print(f"Total: {len(tids)}")
        print(f"Success: {s_cnt}")
        print(f"Failed: {f_cnt}")

    except:
        pass


if __name__ == "__main__":
    app()