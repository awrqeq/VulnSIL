# vulnsil/schemas.py
from pydantic import BaseModel, Field
from enum import Enum
from typing import List, Optional, Dict, Any

class DecisionEnum(str, Enum):
    VULNERABLE = "VULNERABLE"
    BENIGN = "BENIGN"

class EvidenceChecklist(BaseModel):
    untrusted_source: bool = Field(..., description="Does user/network input enter the function?")
    dangerous_sink: bool = Field(..., description="Are risky functions (e.g., memcpy, strcpy) used?")
    data_flow: bool = Field(..., description="Is there a path from source to sink without validation?")
    mitigation_absent: bool = Field(..., description="Are proper checks (length, boundary) missing?")

class AnalysisResult(BaseModel):
    thought_process: str = Field(..., description="Short step-by-step analysis reasoning.")
    evidence: EvidenceChecklist
    cwe_id: str = Field(..., description="The specific CWE ID (e.g., CWE-120) or 'N/A' if safe.")
    decision: DecisionEnum
    confidence: float = Field(..., description="Model's self-confidence (0.0 to 1.0).")

class KnowledgeBaseEntry(BaseModel):
    """
    RAG 检索条目结构体
    """
    id: int
    original_id: str
    code: str
    label: str
    # [修复] 必须显式包含 cwe_id，否则 Prompt 无法获取 CWE 知识
    cwe_id: Optional[str] = "N/A"
    similarity_score: float = 0.0