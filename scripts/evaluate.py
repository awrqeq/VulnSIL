# scripts/evaluate.py
import sys
import os
import typer
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, roc_auc_score, accuracy_score, f1_score

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vulnsil.database import get_db_session
from vulnsil.models import AnalysisResult, Vulnerability
from vulnsil.utils_log import setup_logging

app = typer.Typer()
log = setup_logging("evaluation")


@app.command()
def eval(split: str = typer.Option(..., help="e.g., 'diversevul_test'")):
    log.info(f"Evaluating split: {split}")

    data = []

    with get_db_session() as db:
        # 获取 Success 状态的任务
        records = db.query(AnalysisResult).join(Vulnerability).filter(
            Vulnerability.name.like(f"{split}%"),
            Vulnerability.status == "Success"
        ).all()

        if not records:
            log.error(f"No 'Success' records found for split '{split}'.")
            return

        for r in records:
            # Calibrated P(Vuln) calculation
            p_vuln = r.calibrated_confidence if r.final_decision == "VULNERABLE" else (1.0 - r.calibrated_confidence)

            # Label extraction
            gt_cwe = r.vuln.cwe_id
            if not gt_cwe or str(gt_cwe).lower() in ['nan', 'none', 'n/a', '']:
                gt_cwe = "Other"

            data.append({
                "gt_label": r.vuln.ground_truth_label,
                "pred_label": 1 if r.final_decision == "VULNERABLE" else 0,
                "pred_score": p_vuln,
                "gt_cwe": gt_cwe
            })

    df = pd.DataFrame(data)
    if df.empty:
        log.error("Dataframe is empty after extraction.")
        return

    # 1. Overall Metrics
    y_true = df['gt_label'].values
    y_pred = df['pred_label'].values
    y_score = df['pred_score'].values

    print("\n" + "=" * 50)
    print(f" OVERALL REPORT: {split}")
    print("=" * 50)
    print(f"ACC: {accuracy_score(y_true, y_pred):.4f}")
    print(f"F1 : {f1_score(y_true, y_pred):.4f}")
    try:
        if len(np.unique(y_true)) > 1:
            print(f"AUC: {roc_auc_score(y_true, y_score):.4f}")
        else:
            print("AUC: N/A (Only one class present)")
    except Exception as e:
        print(f"AUC: Error ({e})")

    print(classification_report(y_true, y_pred, target_names=["Safe", "Vuln"], labels=[0, 1], zero_division=0))

    # 2. CWE Breakdown
    print("\n" + "-" * 50)
    print(" CWE-Specific Detection Rate (Recall for Vuln Samples)")
    print("-" * 50)

    vuln_df = df[df['gt_label'] == 1]

    if len(vuln_df) == 0:
        print("No vulnerable samples in dataset to evaluate Recall.")
    else:
        top_cwes = vuln_df['gt_cwe'].value_counts().head(15).index.tolist()
        print(f"{'CWE ID':<20} | {'Count':<8} | {'Recall':<8}")
        print("-" * 45)

        for cwe in top_cwes:
            sub = vuln_df[vuln_df['gt_cwe'] == cwe]
            # [修复] 确保分母不为0 (理论上由count保证，但更稳健)
            if len(sub) == 0: continue

            detected = sub[sub['pred_label'] == 1]
            recall = len(detected) / len(sub)
            print(f"{cwe:<20} | {len(sub):<8} | {recall:.2%}")

    print("=" * 50 + "\n")


if __name__ == "__main__":
    app()