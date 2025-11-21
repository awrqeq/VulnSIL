# scripts/confidence.py
import sys
import os
import joblib
import numpy as np
import typer
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, precision_recall_curve, classification_report
import lightgbm as lgb

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings
from vulnsil.database import get_db_session
from vulnsil.models import AnalysisResultRecord, Vulnerability
from vulnsil.utils_log import setup_logging

app = typer.Typer()
log = setup_logging("tune_calibration")


def find_optimal_threshold(y_true, y_scores):
    if len(np.unique(y_true)) < 2: return 0.5, 0.0
    precision, recall, thresholds = precision_recall_curve(y_true, y_scores)
    f1_scores = 2 * recall * precision / (recall + precision + 1e-10)
    best_idx = np.argmax(f1_scores)
    best_th = thresholds[best_idx] if best_idx < len(thresholds) else 0.5
    return best_th, f1_scores[best_idx]


@app.command()
def train(train_split: str = typer.Option(..., help="e.g. 'diversevul_train'")):
    X, y = [], []
    with get_db_session() as db:
        records = db.query(AnalysisResultRecord).join(Vulnerability).filter(
            Vulnerability.name.like(f"{train_split}%"),
            Vulnerability.status == "Success"
        ).all()

        if not records:
            log.error("No training data found.")
            return

        log.info(f"Loaded {len(records)} samples. Extracting features...")

        for rec in records:
            # 特征向量提取 (必须与 run_pipeline.py 顺序完全一致!)

            # 1. Code Length Log1p
            log_len = np.log1p(max(0, float(rec.feat_code_len or 0)))

            # 2. Construct Vector
            feats = [
                rec.native_confidence,  # 0
                1.0 if rec.static_has_flow else 0.0,  # 1
                float(rec.static_complexity or 0),  # 2
                float(rec.feat_static_apis_count or 0),  # 3
                log_len,  # 4
                1.0 if rec.feat_is_compressed else 0.0,  # 5
                rec.feature_rag_similarity or 0.0,  # 6
                rec.feat_rag_top1_sim or 0.0,  # 7
                rec.feat_rag_sim_variance or 0.0,  # 8

                # Conflict Features
                float(rec.feat_conflict_disagreement or 0),  # 9
                float(rec.feat_conflict_static_yes_llm_no or 0)  # 10
            ]

            X.append(feats)
            y.append(rec.vuln.ground_truth_label)

    X, y = np.array(X), np.array(y)

    # Split for Internal Validation
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

    log.info(f"Training LGBM on {len(X_train)} samples...")

    model = lgb.LGBMClassifier(n_estimators=300, learning_rate=0.03, max_depth=7, verbose=-1)
    model.fit(X_train, y_train)

    # Find Threshold on Internal Validation Set
    y_probs = model.predict_proba(X_val)[:, 1]
    best_th, best_f1 = find_optimal_threshold(y_val, y_probs)

    try:
        auc = roc_auc_score(y_val, y_probs)
    except:
        auc = 0

    print(f"\n[Internal Validation Result]")
    print(f"AUC: {auc:.4f}, Max F1: {best_f1:.4f} @ Threshold: {best_th:.4f}")

    # Save
    joblib.dump(model, settings.CONFIDENCE_MODEL_PATH)
    log.info(f"Model Saved to {settings.CONFIDENCE_MODEL_PATH}")


if __name__ == "__main__":
    app()