package com.windscribe.vpn.backend.xray

import com.windscribe.vpn.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/** Debug test telemetry: fixed labels and counts only; never addresses, credentials or exception text. */
object XrayDiagnostics {
    data class Snapshot(
        val phase: String,
        val lastFailure: String,
        val counters: Map<String, Long>,
        val tunStats: List<Long>,
    )

    @Volatile private var phase = "idle"

    @Volatile private var lastFailure = "none"
    private val counters = ConcurrentHashMap<String, AtomicLong>()

    @Volatile private var probe: (() -> Long)? = null

    @Volatile private var stats: (() -> LongArray)? = null

    @Volatile private var lastTunStats = emptyList<Long>()

    internal fun phase(value: String) {
        if (BuildConfig.DEBUG) phase = value
    }

    internal fun fail(value: String) {
        if (BuildConfig.DEBUG) lastFailure = value
    }

    internal fun count(
        value: String,
        increment: Long = 1,
    ) {
        if (BuildConfig.DEBUG) counters.getOrPut(value) { AtomicLong() }.addAndGet(increment)
    }

    internal fun attach(
        probe: (() -> Long)?,
        stats: (() -> LongArray)?,
    ) {
        if (BuildConfig.DEBUG) {
            if (stats == null) captureTunStats()
            this.probe = probe
            this.stats = stats
        }
    }

    internal fun reset() {
        if (BuildConfig.DEBUG) {
            counters.clear()
            lastTunStats = emptyList()
            lastFailure = "none"
            phase = "starting"
        }
    }

    fun snapshot(): Snapshot {
        check(BuildConfig.DEBUG)
        captureTunStats()
        return Snapshot(
            phase,
            lastFailure,
            counters.mapValues { it.value.get() },
            lastTunStats,
        )
    }

    private fun captureTunStats() {
        runCatching { stats?.invoke()?.toList() }.getOrNull()?.let { lastTunStats = it }
    }

    suspend fun probeCore(): Long =
        withContext(Dispatchers.IO) {
            check(BuildConfig.DEBUG)
            val run = checkNotNull(probe) { "No debug core probe attached" }
            phase("core_probe")
            try {
                run().also { phase("core_probe_passed") }
            } catch (failure: Exception) {
                fail("core_probe")
                phase("core_probe_failed")
                // Do not expose Go exception text: it can contain endpoint or grant data.
                throw IllegalStateException("Native core probe failed")
            }
        }
}
