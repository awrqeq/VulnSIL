# vulnsil/core/static_analysis/ast_analyzer.py
import logging
import threading
import re
from tree_sitter import Language, Parser
import tree_sitter_c

logger = logging.getLogger(__name__)


class ASTHeuristicAnalyzer:
    """
    多级静态分析器 (Tree-sitter AST + Regex Fallback)
    V4.0: 针对 DiverseVul 数据集 (Linux, Xorg, FFmpeg) 进行全量 Sink 扩展。
    解决当 Joern 解析失败时，Tree-sitter 因清单不全导致的漏报问题。
    """

    def __init__(self):
        self.DANGEROUS_FUNCS = {
            # --- 1. Memory Safety & Buffers (Classic) ---
            'memcpy', 'memmove', 'memset', 'memcmp', 'bcopy', 'memccpy',
            'strcpy', 'strncpy', 'strcat', 'strncat', 'strlen',
            'stpcpy', 'stpncpy', 'wcscpy', 'wcsncpy', 'wcscat', 'wcsncat',
            'sprintf', 'vsprintf', 'swprintf', 'vswprintf', 'snprintf', 'vsnprintf', 'vasprintf',
            'bzero', 'explicit_bzero',

            # --- 2. Heap Management (Extended for Kernel) ---
            'malloc', 'calloc', 'realloc', 'alloca', 'free',
            'valloc', 'pvalloc', 'aligned_alloc',
            'strdup', 'strndup', 'memdup', 'wcsdup',
            'av_malloc', 'av_realloc', 'av_free', 'g_malloc', 'g_malloc0', 'g_free',
            # Linux Generic
            'kmalloc', 'kzalloc', 'kfree', 'vmalloc', 'kvfree', 'devm_kzalloc',
            # Linux Slab/SKB (New!)
            'kmem_cache_alloc', 'kmem_cache_zalloc', 'kmem_cache_free', 'kmemdup',
            'kfree_skb', 'dev_kfree_skb', 'consume_skb',

            # --- 3. Numeric & ID ---
            'atoi', 'atol', 'atoll', 'atof',
            'strtol', 'strtoul', 'strtoll', 'strtoull',
            'strtod', 'strtof', 'strtold',
            'strtoimax', 'strtoumax',
            'simple_strtoul', 'simple_strtol',
            'idr_find', 'idr_remove',  # Kernel ID management

            # --- 4. Input Validation & Injection ---
            'gets', 'gets_s', 'scanf', 'fscanf', 'sscanf',
            'vscanf', 'vfscanf', 'vsscanf',
            'system', 'popen', 'pclose',
            'exec', 'execl', 'execlp', 'execle', 'execv', 'execvp', 'execvpe',
            'WinExec', 'ShellExecute', 'CreateProcess', 'CreateProcessAsUser',
            'dlopen', 'dlsym', 'LoadLibrary', 'GetProcAddress',

            # --- 5. File/Path/IO ---
            'open', 'fopen', 'freopen', 'openat', 'fdopen',
            'read', 'fread', 'pread', 'write', 'fwrite', 'pwrite',
            'unlink', 'remove', 'rename', 'mkdir', 'rmdir', 'chdir',
            'realpath', 'getcwd', 'access', 'chmod', 'chown',
            'tmpfile', 'tmpnam', 'mkstemp', 'mktemp',

            # --- 6. Kernel Data Copy & Macros (Must include underscores) ---
            'copy_from_user', 'copy_to_user', '_copy_from_user', '_copy_to_user',
            '__copy_from_user', '__copy_to_user',  # (New! Double underscore)
            'get_user', 'put_user', '__get_user', '__put_user',
            'sock_recvmsg', 'sock_sendmsg',

            # --- 7. Kernel Subsystems (Block / Net / Concurrency) ---
            # Concurrency & Locking (New!)
            'atomic_read', 'atomic_set', 'atomic_inc', 'atomic_dec',
            'spin_lock', 'spin_unlock', 'mutex_lock', 'mutex_unlock',
            # Networking Queues (New!)
            'skb_dequeue', 'skb_queue_tail', 'skb_queue_head', 'skb_peek', 'skb_unlink',
            # Block Device / IO (New!)
            'blk_execute_rq', '__blk_send_generic', 'blk_execute_rq_nowait',
            'sg_io', 'bsg_read', 'bsg_write',

            # --- 8. X11 / Xorg ---
            'dixLookupDevice', 'dixLookup', 'AttachDevice', 'RemoveDevice', 'GetMaster',

            # --- 9. Crypto & Misc ---
            'MD4', 'MD5', 'SHA1', 'crypt', 'rand', 'srand', 'getenv', 'setenv', 'putenv',
            'rc4_hmac_md5', 'EVP_EncryptInit'
        }
        # 预编译正则 (Regex Fallback)，增加 \b 确保精确匹配函数名，避免匹配到变量名
        self.regex_patterns = {
            api: re.compile(r'\b' + re.escape(api) + r'\b')
            for api in self.DANGEROUS_FUNCS
        }

        # === 2. 核心修复逻辑 ===
        try:
            self.LANG_C = Language(tree_sitter_c.language())
            self.parser = Parser(self.LANG_C)
            self._lock = threading.Lock()

            # [修复方案]: 定义多个备选查询语法，依次尝试
            # 现在的 library 有的版本需要字段名 (function: ...), 有的不允许

            queries_to_try = [
                # 1. 标准 V1: 带字段名
                """
                (call_expression function: (identifier) @func_name)
                """,
                # 2. 标准 V1 补充: 结构体调用 obj->func()
                """
                (call_expression function: (field_expression field: (identifier) @func_name))
                """,
                # 3. 兼容 V0 (无字段名): (call_expression (identifier))
                """
                (call_expression (identifier) @func_name)
                """,
                # 4. 兼容 V0 补充:
                """
                (call_expression (field_expression (identifier) @func_name))
                """
            ]

            self.query_call = None
            valid_queries = []

            # 逐个测试查询语句，哪个能用加哪个
            for q_str in queries_to_try:
                try:
                    self.LANG_C.query(q_str)
                    valid_queries.append(q_str)
                except Exception:
                    continue  # 忽略不支持的语法

            if valid_queries:
                # 合并所有能用的语句
                combined_q = "\n".join(valid_queries)
                self.query_call = self.LANG_C.query(combined_q)
                # logger.info(f"Tree-sitter query init success with {len(valid_queries)} patterns.")
            else:
                raise RuntimeError("No compatible Tree-sitter query syntax found.")

        except Exception as e:
            # 如果实在都不行，只报警告（黄色），不报错误（红色），让用户知道正在用 Regex
            logger.warning(f"AST Engine Init skipped: {e}. Running in Regex-Only Mode (Robustness Guaranteed).")
            self.parser = None

    def scan(self, code: str):
        found_apis = set()

        # 1. 优先 AST
        if self.parser and self.query_call:
            try:
                with self._lock:
                    tree = self.parser.parse(code.encode('utf-8', errors='ignore'))

                if hasattr(self.query_call, 'captures'):
                    for cap in self.query_call.captures(tree.root_node):
                        node = cap[0] if isinstance(cap, tuple) else cap
                        # 提取函数名
                        name = code[node.start_byte:node.end_byte].strip()
                        if name in self.DANGEROUS_FUNCS:
                            found_apis.add(name)

                elif hasattr(self.query_call, 'matches'):
                    for _, match in self.query_call.matches(tree.root_node):
                        nodes = match.values() if isinstance(match, dict) else match
                        n_list = nodes if isinstance(nodes, list) else [nodes]
                        for node in n_list:
                            if isinstance(node, list):  # deep nested check
                                for sub in node:
                                    name = code[sub.start_byte:sub.end_byte].strip()
                                    if name in self.DANGEROUS_FUNCS: found_apis.add(name)
                            else:
                                name = code[node.start_byte:node.end_byte].strip()
                                if name in self.DANGEROUS_FUNCS: found_apis.add(name)
            except Exception:
                pass

                # 2. 正则 Fallback (永远可靠的最后一道防线)
        if not found_apis:
            for api, pattern in self.regex_patterns.items():
                if pattern.search(code):
                    found_apis.add(api)

        return (len(found_apis) > 0), list(found_apis)