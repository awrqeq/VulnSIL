# VulnSIL/vulnsil/core/llm/vllm_client.py
import requests
import json
import numpy as np
import logging
from pydantic import ValidationError
from config import settings
from vulnsil.schemas import AnalysisResult

# 复用主日志配置
logger = logging.getLogger(__name__)


class VLLMClient:
    def generate(self, prompt: str):
        payload = {
            "model": settings.LLM_MODEL_NAME,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,

            # [修复核心]: 增加最大生成长度，防止长思维链导致 JSON 截断
            # 512 -> 2048，预留足够空间给 thought_process 和 evidence
            "max_tokens": 2048,
            # [新增关键参数]: 重复惩罚 1.1 
            "repetition_penalty": 1.1,
            # 强制 Pydantic Schema 约束，确保 JSON 格式
            "guided_json": AnalysisResult.model_json_schema(),
            "logprobs": True
        }

        try:
            resp = requests.post(
                settings.LLM_API_URL,
                json=payload,
                # [优化]: 生成长度增加后，推理耗时会变长，放宽超时限制
                timeout=240
            )

            if resp.status_code != 200:
                logger.error(f"LLM API HTTP {resp.status_code}: {resp.text[:200]}")
                return None, 0.0

            data = resp.json()

            content = data['choices'][0]['message']['content']
            logprobs = data['choices'][0]['logprobs']['content']

            # 计算原生置信度: 取所有 decision path tokens 的概率几何平均或算术平均
            if logprobs:
                probs = [np.exp(lp['logprob']) for lp in logprobs]
                native_conf = float(np.mean(probs))
            else:
                native_conf = 0.5

            # [新增]: 增加专门的校验错误捕获
            # 即使 max_tokens 增加，极端情况下仍可能失败，这里捕获错误防止 Pipeline 崩溃
            try:
                result = AnalysisResult.model_validate_json(content)

                # 归一化逻辑：修复模型输出 80.0 而非 0.8 的情况
                if result.confidence > 1.0:
                    logger.warning(
                        f"Detected abnormal confidence {result.confidence}, normalizing to {result.confidence / 100.0}")
                    result.confidence = result.confidence / 100.0

                # 再次兜底，确保不越界
                result.confidence = max(0.0, min(1.0, result.confidence))

                return result, native_conf

            except ValidationError as e:
                logger.error(f"JSON Validation Failed: {str(e)[:200]}...")
                return None, 0.0

        except requests.exceptions.RequestException as e:
            # 网络层错误
            logger.error(f"LLM Connection Failed: {e}")
            return None, 0.0
        except Exception as e:
            # 解析或其他错误
            logger.error(f"LLM Inference/Parse Error: {e}")
            return None, 0.0