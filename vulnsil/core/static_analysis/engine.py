# vulnsil/core/static_analysis/engine.py
import os
import subprocess
import json
import tempfile
import logging
from typing import Tuple, Dict, List

from config import settings
from vulnsil.core.static_analysis.compressor import SemanticCompressor

try:
    from vulnsil.core.static_analysis.ast_analyzer import ASTHeuristicAnalyzer
except ImportError:
    ASTHeuristicAnalyzer = None

logger = logging.getLogger(__name__)


class DualEngineAnalyzer:
    """
    Static Analysis Engine v6.0 (Batch Optimized)
    核心特性:
    - Batch Analysis: 一次 JVM 启动分析 N 个函数 (消除冷启动开销，提速 ~50倍)
    - RAM Disk I/O: 优先使用 /dev/shm
    - Full Sink Coverage: 集成最新的 AST 补漏逻辑
    """

    def __init__(self):
        try:
            self.compressor = SemanticCompressor()
        except Exception as e:
            logger.warning(f"Compressor Init Failed: {e}")
            self.compressor = None

        self.ast_engine = None
        if ASTHeuristicAnalyzer:
            try:
                self.ast_engine = ASTHeuristicAnalyzer()
                logger.info("AST Heuristic Analyzer loaded.")
            except Exception as e:
                logger.warning(f"AST Init Error: {e}")

        self.script_template = ""
        if os.path.exists(settings.JOERN_SCRIPT_PATH):
            with open(settings.JOERN_SCRIPT_PATH, 'r', encoding='utf-8') as f:
                self.script_template = f.read()

        # [JVM Tuning]: 批处理模式内存给大一点
        self.joern_env = os.environ.copy()
        # 初始512M，最大4G，Server模式加快JIT
        self.joern_env["JAVA_OPTS"] = "-Xms512m -Xmx4g -server"
        self.joern_env["_JAVA_OPTIONS"] = "-Xms512m -Xmx4g -XX:+UseSerialGC"

        # Shim Header (保持最新版，含 Kernel Typedefs)
        self.shim_header = """
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        #include <stddef.h>
        #include <stdint.h>
        #include <limits.h>
        #include <stdbool.h>
        #include <sys/types.h>
        #include <unistd.h>

        typedef unsigned char u8;
        typedef unsigned short u16;
        typedef unsigned int u32;
        typedef unsigned long long u64;
        typedef signed char s8;
        typedef signed short s16;
        typedef signed int s32;
        typedef signed long long s64;
        typedef unsigned int __u32;
        typedef unsigned int __be32;
        typedef unsigned long long __u64;
        typedef long long atomic64_t;
        typedef int atomic_t;

        #define __user
        #define __kernel
        #define __iomem
        #define __init
        #define __exit
        #define __force
        #define __must_check
        #define likely(x) (x)
        #define unlikely(x) (x)
        #define asmlinkage
        #define __attribute__(x) 

        #ifndef NULL
        #define NULL ((void*)0)
        #endif
        \n"""

    def _wrap_code_batch(self, code: str, task_id: int) -> str:
        """批处理 Wrap: 将 main 替换为 task_{id}，防止同目录下符号冲突"""
        # 如果代码里自带函数定义(有花括号)，只加头文件
        if "{" in code and "}" in code:
            return self.shim_header + code
        # 否则包裹成唯一函数名
        return f"{self.shim_header}\nint task_{task_id}(int argc, char** argv) {{\n{code}\nreturn 0;\n}}"

    def analyze_batch(self, tasks: List[dict]) -> Dict[int, Dict]:
        """
        [核心] 批处理静态分析
        Input: List of {'id': int, 'code': str}
        Output: Dict { task_id: features_dict }
        """
        # 1. 初始化默认结果 (Fail Safe)
        results_map = {}
        for t in tasks:
            results_map[t['id']] = {
                "success": False, "has_data_flow": False, "complexity": 0, "apis": []
            }

        if not os.path.exists(settings.JOERN_CLI_PATH) or not self.script_template:
            return self._run_ast_fallback_batch(tasks, results_map)

        # 2. 准备批量文件 (/dev/shm)
        temp_dir_base = "/dev/shm" if os.path.exists("/dev/shm") else None

        try:
            with tempfile.TemporaryDirectory(prefix="vuln_batch_", dir=temp_dir_base) as work_dir:
                src_dir = os.path.join(work_dir, "src")
                os.makedirs(src_dir, exist_ok=True)

                # Batch Dump
                for t in tasks:
                    tid = t['id']
                    raw = t['code']
                    # Compress
                    if self.compressor and len(raw) > settings.COMPRESSION_TRIGGER_LEN:
                        code = self.compressor.compress(raw, settings.MAX_CODE_TOKENS_INPUT)
                    else:
                        code = raw

                    final_code = self._wrap_code_batch(code, tid)
                    # Filename: ID.c (Crucial for mapping back)
                    with open(os.path.join(src_dir, f"{tid}.c"), "w", encoding="utf-8") as f:
                        f.write(final_code)

                # Path Setup
                cpg_path = os.path.join(work_dir, "cpg.bin")
                res_path = os.path.join(work_dir, "result.json")
                run_sc = os.path.join(work_dir, "query.sc")

                # 3. Joern Parse (Bulk) -> 生成整个目录的图
                # 超时时间放宽到 120s (处理 1000 个文件)
                cmd_parse = ["/bin/bash", settings.JOERN_PARSE_PATH, src_dir, "--output", cpg_path]
                subprocess.run(
                    cmd_parse, capture_output=True, timeout=120, env=self.joern_env
                )

                if os.path.exists(cpg_path):
                    # 4. Joern Query
                    safe_cpg = cpg_path.replace("\\", "/")
                    safe_out = res_path.replace("\\", "/")
                    # 使用新版 query.sc (支持List输出)
                    script_content = self.script_template.replace("{{CPG_FILE}}", safe_cpg).replace("{{OUT_FILE}}",
                                                                                                    safe_out)

                    with open(run_sc, "w") as f:
                        f.write(script_content)

                    # Run Query Script
                    subprocess.run(
                        [settings.JOERN_CLI_PATH, "--script", run_sc],
                        capture_output=True, timeout=120, cwd=work_dir, env=self.joern_env
                    )

                    # 5. Read & Map Results
                    if os.path.exists(res_path):
                        with open(res_path, 'r', encoding="utf-8") as f:
                            try:
                                raw_json = json.load(f)
                                if isinstance(raw_json, list):
                                    for item in raw_json:
                                        # Map "12345.c" -> 12345
                                        filename = os.path.basename(item.get("filename", ""))
                                        if filename.endswith(".c"):
                                            try:
                                                tid = int(filename.replace(".c", ""))
                                                if tid in results_map:
                                                    results_map[tid]['success'] = True
                                                    results_map[tid]['has_data_flow'] = item.get('has_data_flow', False)
                                                    results_map[tid]['complexity'] = item.get('complexity', 0)
                                                    results_map[tid]['apis'] = item.get('apis', [])
                                            except ValueError:
                                                pass
                            except json.JSONDecodeError:
                                pass
        except Exception as e:
            logger.error(f"Batch Analysis Error: {e}")

        # 6. Global AST Fallback & Feature Fusion
        # 即使 Joern 跑出来了，也用 AST 扫一遍做补充 (Merge APIS)
        # 如果 Joern 没跑出来 (Success=False)，AST 就是主力
        if self.ast_engine:
            for t in tasks:
                tid = t['id']
                res = results_map[tid]

                ast_risky, ast_apis = self.ast_engine.scan(t['code'])  # 扫源码

                # Merge APIs (De-duplicate)
                merged = set(res['apis'])
                merged.update(ast_apis)
                res['apis'] = list(merged)

                # Logic: Joern Fail + AST Risky => Data Flow True (Pessimistic)
                if not res['success'] and ast_risky:
                    res['has_data_flow'] = True

        return results_map

    def _run_ast_fallback_batch(self, tasks, results_map):
        """如果完全没有 Joern 环境，只跑 AST"""
        if self.ast_engine:
            for t in tasks:
                risky, apis = self.ast_engine.scan(t['code'])
                results_map[t['id']]['apis'] = apis
                if risky: results_map[t['id']]['has_data_flow'] = True
        return results_map

    # 兼容旧接口 (保留给单条测试使用)
    def analyze(self, code: str) -> Tuple[Dict, str]:
        dummy_task = {'id': 0, 'code': code}
        res_map = self.analyze_batch([dummy_task])
        return res_map[0], code