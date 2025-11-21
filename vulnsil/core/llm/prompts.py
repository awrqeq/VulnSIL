# vulnsil/core/llm/prompts.py
from typing import List
from vulnsil.schemas import KnowledgeBaseEntry
from config import settings
import logging

log = logging.getLogger("prompts")

class PromptManager:
    """
    Advanced Prompt Engineering for Vulnerability Detection.
    Uses Role-Playing + Chain-of-Thought + Few-Shot RAG + Static Clues.
    """

    # System Prompt: 定义核心人设和思维框架
    # System Prompt: 定义核心人设和思维框架 (V2.0: 强调系统编程上下文)
    SYSTEM_PROMPT = """You are an Expert Security Auditor specializing in C/C++ System Programming (Linux Kernel, Drivers, Embedded). 
            Your mission is to analyze source code functions to identify Critical Security Vulnerabilities (e.g., Buffer Overflows, UAF, Race Conditions, Integer Overflows).
            
            **GUIDELINES**:
            1. **Trace Data Flow**: Manually simulate how user input propagates to Sinks (e.g., copy_from_user, memcpy, malloc).
            2. **Verify Sanitization**: Check if proper boundary checks (e.g., len < MAX) exist *before* the sink.
            3. **Context**: Assume inputs from external sources (network, user space, files) are tainted.
            4. **Evidence**: Do not ignore objective hints from Static Analysis tools.
            
            **RESPONSE FORMAT** (Valid JSON Only):
            {
                "thought_process": "Step-by-step reasoning..." (Do not repeat the same sentence or code block),
                "evidence": {"untrusted_source": bool, "dangerous_sink": bool, "data_flow": bool, "mitigation_absent": bool},
                "final_decision": "VULNERABLE" or "BENIGN",
                "confidence": float (0.0 to 1.0)
            }
            """

    # RAG Template: 清晰的参考案例结构
    RAG_TEMPLATE = """
            [REF ID: {original_id}]
            - Vulnerability Type: {case_label}
            - Similarity: {similarity:.2f}
            - Code Snippet:
            ```c
            {code}
            ```
            """

    # Main Template: 结构化输入，强调各部分的重要性
    MAIN_TEMPLATE = """
           **SECTION 1: OBJECTIVE CLUES (From Static Tools)**
           [Analysis Report]
             - Complexity Level: {complexity_desc}
             - Risky APIs Detected: {api_list}
             - Dangerous Data Flow Detected: **{has_flow}**
             {cwe_hint_block}

           **SECTION 2: HISTORICAL KNOWLEDGE**
           Reference vulnerabilities sharing logic with target:
           {rag_block}

           **SECTION 3: TARGET CODE**
           Audit this function for security defects:
           ```c
           {target_code}
           ```

           **INSTRUCTIONS**
           1. Check usages of **Risky APIs** listed above.
           2. Synthesize Static Report and Historical References.
           3. If Static Analysis says "YES", verify the flow.
           4. Conclude: VULNERABLE or BENIGN?
           """

    @staticmethod
    def build_prompt(
            target_code: str,
            rag_entries: List[KnowledgeBaseEntry],
            static_features: dict = None,
            flow_status_desc: str = "UNKNOWN"
    ) -> str:

        if static_features is None: static_features = {}

        # --- 1. API 列表格式化 (逻辑增强) ---
        # 现在的引擎能捕获大量 API，我们需要防止 Context 爆炸
        raw_apis = static_features.get("apis", [])
        if raw_apis:
            # 去重
            unique = sorted(list(set(raw_apis)))
            # 策略：只取前 12 个，并在结尾加 ... 如果溢出
            if len(unique) > 12:
                display_apis = unique[:12]
                api_str = "[" + ", ".join(display_apis) + ", ...]"
            else:
                api_str = "[" + ", ".join(unique) + "]"
        else:
            api_str = "None detected (Note: Parser might have missed custom wrappers)"

        # --- 2. 复杂度文案优化 (逻辑修正) ---
        # 防止 Complexity: 0 误导 LLM
        comp_val = static_features.get("complexity", 0)
        if comp_val > 0:
            complexity_desc = str(comp_val)
        else:
            # 显式告知 LLM 分析器可能失效了，让它更依赖自己的判断
            complexity_desc = "Unknown (Parsing incomplete, analyze manually)"

        # --- 3. 动态 Token 预算 ---
        # 使用 settings 配置，但保留 safety margin
        MAX_CTX = settings.LLM_MAX_MODEL_LEN
        # 预留给 Output (512) + System (200) + Template (300) + Features (200) ≈ 1200
        # 新增了 API 列表的消耗，需加大预留
        SAFE_MARGIN = 1500

        # 裁剪目标代码
        # Llama3 tokenizer 大概 1 token ≈ 3-4 chars，但为了安全按 1 token ≈ 2.5 chars 估算
        code_limit_chars = (MAX_CTX - SAFE_MARGIN) * 3
        # 考虑到 compressor 已经做过处理，这里只做最后的硬截断
        if len(target_code) > code_limit_chars:
            target_code_trunc = target_code[:int(code_limit_chars)] + "\n...[Truncated]"
        else:
            target_code_trunc = target_code

        # 计算剩余给 RAG 的空间 (简单的字符级估算)
        current_used_chars = len(PromptManager.MAIN_TEMPLATE) + len(target_code_trunc) + len(api_str) + 500
        rag_budget_chars = (MAX_CTX * 3.5) - current_used_chars

        # --- 4. RAG 组装 ---
        cwe_hint_msg = ""
        if rag_entries and rag_entries[0].similarity_score > 0.6:
            top_cwe = rag_entries[0].cwe_id
            if top_cwe and str(top_cwe).upper() != "N/A":
                cwe_hint_msg = f"\n[Expert Insight]\nHigh similarity to {top_cwe} pattern. Focus check on {top_cwe}."

        rag_block = ""
        if rag_budget_chars < 200:
            rag_block = "(References omitted due to context limit)"
        elif not rag_entries:
            rag_block = "(No high-similarity historical patterns found)"
        else:
            snippets = []
            used_chars = 0
            for entry in rag_entries:
                c_lbl = f"Confirmed {entry.cwe_id}" if (entry.cwe_id and entry.cwe_id != "N/A") else "Vuln"

                snip = PromptManager.RAG_TEMPLATE.format(
                    original_id=entry.original_id,
                    similarity=entry.similarity_score,
                    case_label=c_lbl,
                    code=entry.code[:600]  # 单个 RAG 片段也做截断
                )

                if used_chars + len(snip) < rag_budget_chars:
                    snippets.append(snip)
                    used_chars += len(snip)
                else:
                    break
            rag_block = "".join(snippets) if snippets else "(References omitted)"

        return PromptManager.MAIN_TEMPLATE.format(
            complexity_desc=complexity_desc,
            api_list=api_str,
            has_flow=flow_status_desc,
            cwe_hint_block=cwe_hint_msg,
            rag_block=rag_block,
            target_code=target_code_trunc
        )