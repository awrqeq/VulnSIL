# vulnsil/exceptions.py

class VulnSILError(Exception):
    """VulnSIL 项目的基础异常类"""
    def __init__(self, message: str, context: dict = None):
        super().__init__(message)
        self.context = context or {}

class PipelineConfigError(VulnSILError):
    """配置错误 (如路径不存在、环境变量缺失)"""
    pass

class StaticAnalysisError(VulnSILError):
    """静态分析引擎相关错误 (Joern/Tree-sitter)"""
    pass

class JoernExecutionError(StaticAnalysisError):
    """Joern 脚本执行失败或超时"""
    pass

class ParsingError(StaticAnalysisError):
    """代码解析或 AST 提取失败"""
    pass

class RetrievalError(VulnSILError):
    """RAG 检索模块错误"""
    pass

class IndexNotFoundError(RetrievalError):
    """向量索引或 BM25 索引文件丢失"""
    pass

class LLMError(VulnSILError):
    """LLM 推理相关错误"""
    pass

class LLMInferenceError(LLMError):
    """调用 vLLM API 失败 (HTTP 500/超时)"""
    pass

class ModelValidationError(LLMError):
    """虽然使用了 Guided Decoding，但结果仍无法通过 Pydantic 校验"""
    pass