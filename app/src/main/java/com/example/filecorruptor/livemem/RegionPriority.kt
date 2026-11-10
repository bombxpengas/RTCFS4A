package com.example.filecorruptor.livemem

/**
 * Which memory is worth scanning for an emulated console's RAM (port of tools/emu-lab emulab/regions.py,
 * which was tuned on a real Android capture: ~87% of a phone process's resident memory — executable code,
 * ART heaps, system libraries, GPU buffers — can never hold console RAM).
 *
 *   HIGH  anonymous / shared writable memory (unnamed, [anon:scudo:*], [heap], .bss, memfd/ashmem)
 *   LOW   other file-backed writable memory, and ROM-like file mappings
 *   SKIP  everything that can't hold RAM
 */
object RegionPriority {
    enum class Level { HIGH, LOW, SKIP }

    private val SKIP_EXT = listOf(".vdex", ".odex", ".oat", ".art", ".dex", ".apk", ".jar", ".ttf", ".otf", ".db", ".pma", ".so", ".relro")
    private val SKIP_PATH = listOf(
        "dalvik", "jit-cache", "jit-zygote", "kgsl", "/dev/", "__properties__", "linker_alloc", "[stack", "[vvar", "[vdso",
        "[vsyscall", "/system/", "/apex/", "/vendor/", "/product/", "/system_ext/", "/odm/", "framework", "gralloc", "dmabuf",
        "[anon:guard", "gwp-asan", "pre-zygote", "boot-image", "app_webview", "u:object_r"
    )
    private val ROMLIKE = listOf(".z64", ".n64", ".v64", ".rom", ".gba", ".nds", ".nes", ".sfc", ".smc", ".gb", ".gbc", ".md", ".bin", ".iso", ".cso")

    fun classify(r: MemoryRegion): Level {
        val p = r.path
        val low = p.lowercase()
        if (r.perms.isEmpty() || r.perms[0] != 'r') return Level.SKIP
        if (r.isExecutable) return Level.SKIP
        if (r.size < 4096) return Level.SKIP
        if (ROMLIKE.any { low.endsWith(it) }) return Level.LOW
        if (SKIP_PATH.any { low.contains(it) }) return Level.SKIP
        if (SKIP_EXT.any { low.endsWith(it) }) return Level.SKIP
        if (!r.isWritable) return Level.SKIP
        if (p.isEmpty() || p.startsWith("[anon") || p == "[heap]" || p.startsWith("/memfd:") || low.contains("ashmem") || low.contains("anon_shmem")) return Level.HIGH
        return Level.LOW
    }

    /** HIGH first, biggest first, then LOW — the order the native finder scans in. */
    fun scanOrder(regions: List<MemoryRegion>): List<MemoryRegion> =
        regions.filter { classify(it) != Level.SKIP }
            .sortedWith(compareBy<MemoryRegion> { if (classify(it) == Level.HIGH) 0 else 1 }.thenByDescending { it.size })
}
