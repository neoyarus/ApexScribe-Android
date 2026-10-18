package com.windscribe.vpn.backend.xray

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.windscribe.vpn.BuildConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.withContext
import libv2ray.CoreCallbackHandler
import libv2ray.CoreController
import libv2ray.Libv2ray
import java.net.Inet4Address
import java.net.InetAddress
import java.net.ServerSocket
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

/** Explicit debug-only outbound isolation probe. No config or grant leaves memory. */
object XrayDebugProbe {
    data class Result(
        val passed: Boolean,
        val delayMillis: Long,
        val diagnostics: XrayDiagnostics.Snapshot,
    )

    suspend fun standalone(
        context: Context,
        config: XrayTunnelConfig,
    ): Result =
        withContext(Dispatchers.IO) {
            check(BuildConfig.DEBUG)
            check(XrayRuntime.state.value == XrayRuntimeState.Stopped)
            val connectivity = context.getSystemService(ConnectivityManager::class.java)
            check(
                connectivity.allNetworks.none {
                    connectivity.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ==
                        true
                },
            )
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            var dialer: ProtectedDialer? = null
            var core: CoreController? = null
            XrayDiagnostics.reset()
            XrayDiagnostics.phase("standalone_resolve")
            var passed = false
            var delay = -1L
            try {
                val endpoint = InetAddress.getAllByName(config.vless.host).first { it is Inet4Address }
                // There is no VPN in this diagnostic mode, as asserted above. The same
                // allowlisted relay and authentication are exercised without TUN routing.
                val relay = ProtectedDialer(scope, endpoint, config.vless.port) { true }.also { dialer = it }
                go.Seq.setContext(context.applicationContext)
                val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
                Libv2ray.initCoreEnv(context.filesDir.absolutePath, Base64.getUrlEncoder().withoutPadding().encodeToString(key))
                val controller =
                    Libv2ray
                        .newCoreController(
                            object : CoreCallbackHandler {
                                override fun startup(): Long = 0

                                override fun shutdown(): Long = 0

                                override fun onEmitStatus(
                                    code: Long,
                                    status: String?,
                                ): Long = 0
                            },
                        ).also { core = it }
                val port = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }
                controller.startLoop(
                    XrayConfig.create(
                        config.vless,
                        checkNotNull(endpoint.hostAddress),
                        port,
                        UUID.randomUUID().toString(),
                        UUID.randomUUID().toString(),
                        relay.port,
                        relay.username,
                        relay.password,
                    ),
                    0,
                )
                XrayDiagnostics.attach({ controller.measureDelay("https://api.ipify.org") }, null)
                delay = XrayDiagnostics.probeCore()
                passed = delay >= 0
            } catch (_: Exception) {
                XrayDiagnostics.fail("standalone_probe")
            } finally {
                XrayDiagnostics.attach(null, null)
                XrayDiagnostics.phase("standalone_cleanup_dialer")
                runCatching { dialer?.close() }
                XrayDiagnostics.phase("standalone_cleanup_core")
                runCatching { core?.stopLoop() }
                scope.cancel()
                XrayDiagnostics.phase("standalone_complete")
            }
            Result(passed, delay, XrayDiagnostics.snapshot())
        }
}
