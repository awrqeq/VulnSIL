# vulnsil/core/static_analysis/engine.py
import importlib.util
import json
import logging
import os
import subprocess
import tempfile
from typing import Dict, List, Tuple

from config import settings
from vulnsil.core.static_analysis.compressor import SemanticCompressor

ast_spec = importlib.util.find_spec("vulnsil.core.static_analysis.ast_analyzer")
if ast_spec is not None and ast_spec.loader is not None:
    ast_module = importlib.util.module_from_spec(ast_spec)
    ast_spec.loader.exec_module(ast_module)
    ASTHeuristicAnalyzer = getattr(ast_module, "ASTHeuristicAnalyzer", None)
else:
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
        self.joern_env["JAVA_OPTS"] = settings.JOERN_JAVA_OPTS
        self.joern_env["_JAVA_OPTIONS"] = settings.JOERN_JAVA_OPTIONS

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
        temp_dir_base = settings.STATIC_TMP_DIR if os.path.exists(settings.STATIC_TMP_DIR) else None

        try:
            with tempfile.TemporaryDirectory(prefix="vuln_batch_", dir=temp_dir_base) as work_dir:
                src_dir = os.path.join(work_dir, "src")
                os.makedirs(src_dir, exist_ok=True)

                self._dump_batch_files(tasks, src_dir)

                # Path Setup
                cpg_path = os.path.join(work_dir, "cpg.bin")
                res_path = os.path.join(work_dir, "result.json")
                run_sc = os.path.join(work_dir, "query.sc")

                # 3. Joern Parse (Bulk) -> 生成整个目录的图
                parse_ok = self._run_cpg_generation(src_dir, cpg_path)

                if parse_ok and os.path.exists(cpg_path):
                    self._prepare_and_run_query(cpg_path, res_path, run_sc, work_dir)
                    self._map_results(res_path, results_map)
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

    def _dump_batch_files(self, tasks: List[dict], src_dir: str) -> None:
        """将批次中的代码落盘并添加 Shim 头"""
        for t in tasks:
            tid = t['id']
            raw = t['code']
            if self.compressor and len(raw) > settings.COMPRESSION_TRIGGER_LEN:
                code = self.compressor.compress(raw, settings.MAX_CODE_TOKENS_INPUT)
            else:
                code = raw

            final_code = self._wrap_code_batch(code, tid)
            with open(os.path.join(src_dir, f"{tid}.c"), "w", encoding="utf-8") as f:
                f.write(final_code)

    def _run_cpg_generation(self, src_dir: str, cpg_path: str) -> bool:
        """执行 c2cpg 生成步骤并返回是否成功"""
        cmd_parse = ["/bin/bash", settings.JOERN_PARSE_PATH, src_dir, "--output", cpg_path]
        try:
            res = subprocess.run(
                cmd_parse,
                capture_output=True,
                timeout=settings.STATIC_PARSE_TIMEOUT,
                env=self.joern_env,
                check=False,
            )
            if res.returncode != 0:
                logger.warning(
                    f"Joern parse exited {res.returncode}: {res.stderr.decode(errors='ignore')[:200]}"
                )
            return os.path.exists(cpg_path)
        except subprocess.TimeoutExpired:
            logger.error("Joern parse timeout in batch mode.")
        except Exception as exc:
            logger.error(f"Joern parse failed: {exc}")
        return False

    def _prepare_and_run_query(self, cpg_path: str, res_path: str, run_sc: str, work_dir: str) -> None:
        safe_cpg = cpg_path.replace("\\", "/")
        safe_out = res_path.replace("\\", "/")
        script_content = self.script_template.replace("{{CPG_FILE}}", safe_cpg).replace(
            "{{OUT_FILE}}", safe_out
        )

        with open(run_sc, "w") as f:
            f.write(script_content)

        try:
            result = subprocess.run(
                [settings.JOERN_CLI_PATH, "--script", run_sc],
                capture_output=True,
                timeout=settings.STATIC_QUERY_TIMEOUT,
                cwd=work_dir,
                env=self.joern_env,
                check=False,
            )
            if result.returncode != 0:
                logger.warning(
                    f"Joern query exited {result.returncode}: {result.stderr.decode(errors='ignore')[:200]}"
                )
        except subprocess.TimeoutExpired:
            logger.error("Joern query timeout in batch mode.")
        except Exception as exc:
            logger.error(f"Joern query failed: {exc}")

    def _map_results(self, res_path: str, results_map: Dict[int, Dict]) -> None:
        if not os.path.exists(res_path):
            return
        try:
            with open(res_path, 'r', encoding="utf-8") as f:
                raw_json = json.load(f)
        except json.JSONDecodeError:
            logger.error("Invalid JSON returned by Joern query.")
            return
        except Exception as exc:
            logger.error(f"Read result failed: {exc}")
            return

        if not isinstance(raw_json, list):
            logger.warning("Unexpected Joern output format (not list).")
            return

        for item in raw_json:
            filename = os.path.basename(item.get("filename", ""))
            if not filename.endswith(".c"):
                continue
            try:
                tid = int(filename.replace(".c", ""))
            except ValueError:
                continue

            if tid in results_map:
                results_map[tid]['success'] = True
                results_map[tid]['has_data_flow'] = item.get('has_data_flow', False)
                results_map[tid]['complexity'] = item.get('complexity', 0)
                results_map[tid]['apis'] = item.get('apis', [])
