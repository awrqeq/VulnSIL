# scripts/manage_database.py
import sys
import os
import json
import argparse
import logging
from sqlalchemy.orm import Session
from tqdm import tqdm

# 路径适配
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnsil.utils_log import setup_logging
from config import settings
from vulnsil.database import get_db_session, engine, Base
from vulnsil.models import Vulnerability, AnalysisResultRecord, KnowledgeBase

log = logging.getLogger(__name__)


def init_db():
    """初始化/创建数据库表"""
    Base.metadata.create_all(bind=engine)
    log.info(f"Database connected at: {settings.DATABASE_URI}")


def perform_cleanup(db: Session, mode: str):
    """清理工具"""
    if mode == 'recreate':
        log.warning("!!! RECREATE MODE: Dropping database file! !!!")
        db_path = settings.DATABASE_URI.replace("sqlite:///", "")
        if db: db.close()
        engine.dispose()
        if os.path.exists(db_path):
            os.remove(db_path)
        init_db()
        return

    if mode == 'analysis':
        log.info("Action: Clear Analysis Results")
        if not db: return
        db.query(AnalysisResultRecord).delete()
        # 重置所有 Pending 以外的任务
        db.query(Vulnerability).update({Vulnerability.status: 'Pending'})
        db.commit()

    elif mode == 'vulns':
        log.info("Action: Clear All Tasks (Keeping RAG)")
        if not db: return
        db.query(AnalysisResultRecord).delete()
        db.query(Vulnerability).delete()
        db.commit()


def import_split_data(db: Session, filename: str, split_name: str):
    """
    导入数据集到 Vulnerabilities 表
    [修复]: 完美适配 prepare_splits.py 生成的新字段
    """
    file_path = os.path.join(settings.DATA_DIR, filename)

    if not os.path.exists(file_path):
        log.error(f"Data file missing: {file_path}")
        return

    log.info(f"Importing {filename} as '{split_name}'...")

    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    added_count = 0
    skipped_count = 0

    for idx, line in enumerate(tqdm(lines, desc=f"Importing")):
        if not line.strip(): continue
        try:
            item = json.loads(line)

            code = item.get('func') or item.get('code') or item.get('function')
            # 标签读取兼容
            raw_label = item.get('target')
            if raw_label is None: raw_label = item.get('label')

            if not code or raw_label is None: continue

            # [核心修复] 读取新脚本生成的 cwe_id
            # 如果是旧数据格式，兜底读取 cwe 列表
            cwe_val = item.get('cwe_id')
            if not cwe_val:
                # Fallback old list logic
                raw_c = item.get('cwe')
                if isinstance(raw_c, list) and len(raw_c) > 0:
                    cwe_val = str(raw_c[0])
                else:
                    cwe_val = "N/A"

            # 构造唯一 name ID
            # 使用 split_name 区分 train/test
            cid = item.get('commit_id') or "unk"
            # 加入行号索引避免重复
            unique_name = f"{split_name}_{cid}_{idx}"

            # 入库
            vuln = Vulnerability(
                name=unique_name,
                code=code,
                ground_truth_label=int(raw_label),
                cwe_id=cwe_val,
                status="Pending"
            )
            db.add(vuln)
            added_count += 1

        except Exception:
            skipped_count += 1

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        log.error(f"Commit Error: {e}")

    log.info(f"Import Complete. New: {added_count}, Err: {skipped_count}")


def print_database_summary(db: Session):
    total_tasks = db.query(Vulnerability).count()
    results = db.query(AnalysisResultRecord).count()
    rag_count = db.query(KnowledgeBase).count()
    print(f"DB Status | KB: {rag_count} | Tasks: {total_tasks} | Results: {results}")


if __name__ == "__main__":
    setup_logging("manage_db")
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--clear-analysis", action="store_true", help="Reset results")
    group.add_argument("--clear-vulns", action="store_true", help="Clear tasks")
    group.add_argument("--recreate", action="store_true", help="Destroy & Init DB")

    parser.add_argument("--split", type=str, help="Shortcut: imports {split}.jsonl as {split}")

    args = parser.parse_args()

    if args.recreate:
        perform_cleanup(None, 'recreate')
        sys.exit(0)

    init_db()

    with get_db_session() as session:
        if args.clear_analysis:
            perform_cleanup(session, 'analysis')
        elif args.clear_vulns:
            perform_cleanup(session, 'vulns')

        if args.split:
            import_split_data(session, f"{args.split}.jsonl", args.split)

        print_database_summary(session)