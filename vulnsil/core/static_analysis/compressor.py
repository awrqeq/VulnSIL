# vulnsil/core/static_analysis/compressor.py
import logging
from tree_sitter import Language, Parser
import tree_sitter_c

logger = logging.getLogger(__name__)


class SemanticCompressor:
    def __init__(self):
        try:
            self.LANG_C = Language(tree_sitter_c.language())
            self.parser = Parser(self.LANG_C)
        except Exception as e:
            raise RuntimeError(f"Tree-sitter Init Failed: {e}")

        self.FOLD_TYPES = {'compound_statement', 'while_statement', 'for_statement', 'if_statement'}

        # [同步更新]: 必须包含所有高危 API，防止被误折叠
        self.CRITICAL_KEYWORDS = [
            # --- 1. Control Flow ---
            b'return', b'goto', b'break', b'continue', b'throw', b'catch', b'try',
            b'asm', b'__asm', b'#include', b'#define',

            # --- 2. Classic Memory ---
            b'memcpy', b'memmove', b'memset', b'malloc', b'calloc', b'realloc', b'free',
            b'alloca', b'bcopy', b'strdup',

            # --- 3. Strings & Output ---
            b'strcpy', b'strncpy', b'strcat', b'strncat', b'sprintf', b'snprintf',
            b'vsprintf', b'vsnprintf', b'gets', b'scanf', b'sscanf',

            # --- 4. Numeric / Integer Overflow Sources (DiverseVul Update) ---
            b'atoi', b'atol', b'strtol', b'strtoul', b'strtoull', b'simple_strtoul',

            # --- 5. System/Process/Injection ---
            b'system', b'exec', b'popen', b'dlopen', b'LoadLibrary',
            b'fork', b'clone', b'setuid', b'setgid',

            # --- 6. IO & Kernel Sinks ---
            b'open', b'fopen', b'read', b'write', b'recv', b'send',
            b'remove', b'unlink', b'rename',
            b'copy_from_user', b'copy_to_user', b'get_user', b'put_user',

            # --- 7. X11 / Xorg ---
            b'dixLookupDevice', b'AttachDevice', b'RemoveDevice',

            # --- 8. Important Logic ---
            b'if', b'else', b'switch', b'for', b'while', b'do',
            b'assert', b'likely', b'unlikely',

            # --- 9. Crypto ---
            b'MD5', b'SHA1', b'crypt', b'password', b'key', b'secret'
        ]

        self.query_comment = self.LANG_C.query("(comment) @comment")

    def _get_captures(self, query, node):
        """Helper to safely get captures across different library versions"""
        if hasattr(query, 'captures'):
            try:
                return query.captures(node)
            except:
                pass

        # Fallback to matches manually unpacked
        res = []
        if hasattr(query, 'matches'):
            try:
                matches = query.matches(node)
                for _, captures in matches:
                    for items in captures.values():
                        if isinstance(items, list):
                            for i in items: res.append((i, "comment"))
                        else:
                            res.append((items, "comment"))
            except:
                pass
        return res

    def compress(self, code: str, limit: int = 14000) -> str:
        if len(code) < limit:
            return code

        code_bytes = code.encode('utf-8')
        try:
            tree = self.parser.parse(code_bytes)
        except:
            return code[:limit]  # Fallback raw truncation

        ranges_to_hide = []

        captures = self._get_captures(self.query_comment, tree.root_node)
        for item in captures:
            node = item[0] if isinstance(item, tuple) else item
            ranges_to_hide.append((node.start_byte, node.end_byte, b" "))

        def visit(node):
            length = node.end_byte - node.start_byte
            if node.type in self.FOLD_TYPES and length > 400:
                node_text = code_bytes[node.start_byte:node.end_byte]
                # 检查是否包含任何关键 API 或逻辑
                has_critical = any(kw in node_text for kw in self.CRITICAL_KEYWORDS)
                if not has_critical:
                    placeholder = b" /* ... Logic Folded ... */ "
                    ranges_to_hide.append((node.start_byte + 1, node.end_byte - 1, placeholder))
                    return

            for child in node.children:
                visit(child)

        visit(tree.root_node)

        ranges_to_hide.sort(key=lambda x: x[0], reverse=True)

        mod_code = bytearray(code_bytes)
        for start, end, replacement in ranges_to_hide:
            mod_code[start:end] = replacement

        compressed = mod_code.decode('utf-8', errors='ignore')

        if len(compressed) > limit:
            half = limit // 2
            compressed = compressed[:half] + "\n/* ... TRUNCATED ... */\n" + compressed[-half:]

        return compressed