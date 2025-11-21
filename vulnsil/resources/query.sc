import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import java.io.File

// 1. 定义输出路径 (由 Python 动态注入)
val outFile = raw"{{OUT_FILE}}"

try {
  // 2. 加载 CPG (自动识别单文件还是目录)
  val cpgOpt = importCpg(raw"{{CPG_FILE}}")

  if (cpgOpt.isEmpty) {
     val outErr = ujson.Obj("error" -> "CPG Import Failed")
     os.write.over(os.Path(outFile), ujson.Arr(outErr).render(indent=2))
  } else {
      val cpg = cpgOpt.get
      try {
          // 3. 核心 Sink 列表 (Full List: 包含标准C库、DiverseVul 增强、内核专用)
          // 这是一个 Superset，包含了您要求的所有内容
          // ======================================================
          val dangerousSinksNames = Set(
            // --- [1] Memory Safety (Classic CWE-120, 787) ---
            "memcpy", "memmove", "memset", "memcmp", "bcopy", "memccpy",
            "strcpy", "strncpy", "strcat", "strncat", "strlen",
            "sprintf", "vsprintf", "snprintf", "swprintf",
            "vsnprintf", "vasprintf", "vsscanf", "vfscanf",
            "stpcpy", "stpncpy", "wcscpy", "wcsncpy", "wcscat", "wcsncat", // Wide Char
            "bzero", "explicit_bzero", // Kernel/BSD specific

            // --- [2] Input Validation (CWE-20) ---
            "gets", "gets_s", "scanf", "fscanf", "sscanf", "vscanf",

            // --- [3] Heap Management (CWE-416, 400) ---
            "malloc", "calloc", "realloc", "alloca", "free",
            "valloc", "pvalloc", "aligned_alloc",
            "strdup", "strndup", "memdup", "wcsdup", // Implicit alloc

            // Project Specific Allocators (DiverseVul Coverage)
            "av_malloc", "av_realloc", "av_free",         // FFmpeg
            "g_malloc", "g_malloc0", "g_free",            // GLib/QEMU
            "kmalloc", "kzalloc", "kfree", "vmalloc", "kvfree", "devm_kzalloc", // Linux Generic

            // Linux Kernel Advanced Memory (Slab & SKB)
            "kmem_cache_alloc", "kmem_cache_zalloc", "kmem_cache_free", "kmemdup",
            "kfree_skb", "dev_kfree_skb", "consume_skb",

            // --- [4] Numeric & Integer Overflow Sources (CWE-190) ---
            "atoi", "atol", "atoll", "atof",
            "strtol", "strtoul", "strtoll", "strtoull",
            "strtod", "strtof", "strtold",
            "strtoimax", "strtoumax",
            "simple_strtoul", "simple_strtol", // Kernel Utils

            // --- [5] Command/Code Injection (CWE-78, 77) ---
            "system", "popen", "pclose",
            "exec", "execl", "execlp", "execle", "execv", "execvp", "execvpe",
            "WinExec", "ShellExecute", "CreateProcess", "CreateProcessAsUser",
            "dlopen", "dlsym", "LoadLibrary", "GetProcAddress",

            // --- [6] File/Path/IO (CWE-22, TOC/TOU) ---
            "open", "fopen", "freopen", "openat", "fdopen",
            "read", "fread", "pread", "write", "fwrite", "pwrite",
            "recv", "recvfrom", "recvmsg", "send", "sendto", "sendmsg",
            "sock_recvmsg", "sock_sendmsg",
            "unlink", "remove", "rename", "mkdir", "rmdir", "chdir",
            "access", "chmod", "chown", "getcwd", "realpath",
            "tmpfile", "tmpnam", "mkstemp", "mktemp",

            // --- [7] Linux Kernel Specific Data Transfer (CRITICAL) ---
            // Missing these results in FN for ID 121 etc.
            "copy_from_user", "copy_to_user",
            "_copy_from_user", "_copy_to_user",
            "__copy_from_user", "__copy_to_user",
            "get_user", "put_user",
            "__get_user", "__put_user",

            // --- [8] Concurrency & Driver Logic (CWE-362) ---
            "atomic_read", "atomic_set", "atomic_inc", "atomic_dec",
            "spin_lock", "spin_unlock", "mutex_lock", "mutex_unlock",
            "skb_dequeue", "skb_queue_tail", "skb_queue_head", "skb_peek", "skb_unlink",
            "blk_execute_rq", "__blk_send_generic", "blk_execute_rq_nowait",
            "sg_io", "bsg_read", "bsg_write",

            // --- [9] X11 / Xorg / Graphics Specific ---
            "dixLookup", "dixLookupDevice", "AttachDevice", "RemoveDevice", "GetMaster",

            // --- [10] Crypto & Misc & Environment ---
            "MD4", "MD5", "SHA1", "crypt", "rand", "srand",
            "getenv", "setenv", "putenv"
          )

          implicit val context: EngineContext = EngineContext()

          // ======================================================
          // 4. 批处理核心 (Batch Logic): 遍历所有源码文件
          // ======================================================

          // 过滤规则: 只处理 ".c" 结尾的文件 (这是我们在 engine.py 中批量生成的 {ID}.c)
          // 使用 cpg.method.internal 确保不抓取 library function stub
          val results = cpg.method.internal.filter(_.filename.endsWith(".c")).map { method =>

              // filename 类似于 "/dev/shm/vuln_batch_xxx/src/1001.c"
              // Python 端会提取文件名 "1001.c" 来匹配任务
              val currentFilename = method.filename

              // 4.1 API Feature
              val usedApis = method.ast.isCall.name.filter(n =>
                  dangerousSinksNames.exists(d => n.contains(d))
              ).l.distinct

              // 4.2 Complexity
              val complexity = method.controlStructure.size

              // 4.3 Data Flow Analysis
              val sources = method.parameter.l
              val sinks = method.ast.isCall.filter(c =>
                  dangerousSinksNames.exists(d => c.name.contains(d))
              ).argument.l

              val hasFlow = if (sinks.isEmpty || sources.isEmpty) {
                  false
              } else {
                  // 只要有任意一条路从 Source 到 Sink，即视为风险
                  sinks.exists(sink => sink.reachableBy(sources).nonEmpty)
              }

              // Return as a clean map -> JSON Object
              Map(
                  "filename" -> currentFilename,
                  "success" -> true,
                  "apis" -> usedApis,
                  "complexity" -> complexity,
                  "has_data_flow" -> hasFlow
              )
          }.l

          // 5. 输出完整列表
          os.write.over(os.Path(outFile), ujson.write(results, indent=2))

      } catch {
        case e: Exception =>
          val err = Map("success" -> false, "error" -> e.toString)
          // 若内部失败，返回单元素的错误数组，避免 json load 格式错误
          os.write.over(os.Path(outFile), ujson.write(Seq(err), indent=2))
      } finally {
          cpg.close()
      }
  }
} catch {
    case e: Exception =>
       // 最外层错误处理
}