# vulnsil/models.py
from sqlalchemy import Column, Integer, String, Text, Float, Boolean, ForeignKey, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from vulnsil.database import Base


class KnowledgeBase(Base):
    """RAG 知识库"""
    __tablename__ = "knowledge_base"
    id = Column(Integer, primary_key=True, index=True)
    original_id = Column(String, unique=True, index=True)
    code = Column(Text)
    label = Column(String)
    cwe_id = Column(String, nullable=True)
    source_dataset = Column(String)


class Vulnerability(Base):
    """待分析任务"""
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    code = Column(Text)
    ground_truth_label = Column(Integer)
    cwe_id = Column(String, default="N/A")
    status = Column(String, default="Pending")

    result = relationship("AnalysisResultRecord", back_populates="vuln", uselist=False)


class AnalysisResultRecord(Base):
    """分析结果"""
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True)
    vuln_id = Column(Integer, ForeignKey("vulnerabilities.id"), unique=True)

    raw_json = Column(Text)
    final_decision = Column(String)
    cwe_id = Column(String, nullable=True)

    native_confidence = Column(Float)
    calibrated_confidence = Column(Float)

    # --- 特征维度 (共13维) ---
    # 1. Static Base
    static_has_flow = Column(Boolean)
    static_complexity = Column(Integer)
    feat_static_apis_count = Column(Integer)

    # 2. Code Metadata
    feat_code_len = Column(Integer)  # 数据库存原始值，计算时转log1p
    feat_is_compressed = Column(Boolean)

    # 3. RAG Base
    feat_rag_agreement = Column(Float)  # 预留
    feature_rag_similarity = Column(Float)
    feat_rag_top1_sim = Column(Float)
    feat_rag_sim_variance = Column(Float)

    # 4. [创新点C] Conflict Features
    # 意见不合: LLM 与 静态分析结论相左 (0/1)
    feat_conflict_disagreement = Column(Integer)
    # 高风险误报模式: 静态分析报警(1) 但 LLM认为安全(0)
    feat_conflict_static_yes_llm_no = Column(Integer)

    vuln = relationship("Vulnerability", back_populates="result")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


if __name__ == "__main__":
    from vulnsil.database import engine

    Base.metadata.create_all(bind=engine)