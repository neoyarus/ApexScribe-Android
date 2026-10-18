package com.windscribe.vpn.backend.xray

import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.windscribe.common.DNSDetails
import com.windscribe.common.DnsType
import com.windscribe.common.getDNSDetails
import com.windscribe.vpn.R
import com.windscribe.vpn.api.apexguard.ApexContracts
import com.windscribe.vpn.apppreference.PreferencesHelper
import com.windscribe.vpn.apppreference.PreferencesKeyConstants
import com.windscribe.vpn.backend.ProxyDNSManager
import com.windscribe.vpn.backend.VPNState
import com.windscribe.vpn.backend.utils.ExcludedIpHolder
import com.windscribe.vpn.backend.utils.WindNotificationBuilder
import com.windscribe.vpn.backend.utils.startForegroundImmediately
import com.windscribe.vpn.backend.utils.startForegroundSafely
import com.windscribe.vpn.constants.NotificationConstants
import dagger.hilt.android.AndroidEntryPoint
import hev.htproxy.TProxyService
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import libv2ray.CoreCallbackHandler
import libv2ray.CoreController
import libv2ray.Libv2ray
import java.io.File
import java.net.Inet4Address
import java.net.InetAddress
import java.net.ServerSocket
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import javax.inject.Inject
import kotlin.coroutines.coroutineContext

@AndroidEntryPoint
class XrayVpnService : VpnService() {
    @Inject lateinit var preferencesHelper: PreferencesHelper

    @Inject lateinit var excludedIpHolder: ExcludedIpHolder

    @Inject lateinit var notificationBuilder: WindNotificationBuilder

    @Inject lateinit var proxyDNSManager: ProxyDNSManager

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lifecycle = Mutex()
    private var startJob: Job? = null
    private var monitorJob: Job? = null
    private var tun: ParcelFileDescriptor? = null
    private var core: CoreController? = null
    private var dialer: ProtectedDialer? = null
    private var hevStarted = false
    private var configFile: File? = null
    private val runtimeOwner = UUID.randomUUID().toString()
    private var requestToken: String? = null
    private var stopJob: Job? = null

    @Volatile private var destroying = false

    override fun onCreate() {
        startForegroundImmediately(NotificationConstants.SERVICE_NOTIFICATION_ID)
        super.onCreate()
        XrayRuntime.serviceCreated(runtimeOwner, ::requestStop)
        startForegroundSafely(notificationBuilder, NotificationConstants.SERVICE_NOTIFICATION_ID, VPNState.Status.Connecting)
    }

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int,
    ): Int {
        val token = intent?.getStringExtra(REQUEST_TOKEN)
        val config = if (intent?.action == START) XrayRuntime.takePending(token) else null
        if (intent?.action != START || config == null) {
            if (!XrayRuntime.isCurrent(requestToken)) requestStop()
            return START_NOT_STICKY
        }
        if (destroying) return START_NOT_STICKY
        requestToken = token
        startJob?.cancel()
        startJob =
            scope.launch {
                lifecycle.withLock {
                    cleanup()
                    try {
                        check(XrayRuntime.isCurrent(token))
                        startTunnel(config, token)
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (_: Throwable) {
                        cleanup()
                        XrayRuntime.publish(XrayRuntimeState.Failed("VPN tunnel could not start"), token)
                        requestStop()
                    }
                }
            }
        // Credentials stay in memory and are never replayed after process death.
        return START_NOT_STICKY
    }

    private suspend fun startTunnel(
        config: XrayTunnelConfig,
        token: String?,
    ) {
        XrayDiagnostics.reset()
        check(prepare(this) == null) { "VPN permission required" }
        val grant = config.vless
        val endpoint =
            InetAddress.getAllByName(grant.host).firstOrNull { it is Inet4Address }
                ?: error("No IPv4 endpoint")
        check(!endpoint.isAnyLocalAddress && !endpoint.isLoopbackAddress && !endpoint.isMulticastAddress)
        coroutineContext.ensureActive()
        check(XrayRuntime.isCurrent(token))
        val customDns = preferencesHelper.dnsAddress.takeIf { preferencesHelper.dnsMode == PreferencesKeyConstants.DNS_MODE_CUSTOM }
        val dns =
            if (customDns != null && ApexContracts.ipv4(customDns)) {
                DNSDetails(address = customDns, ip = customDns, type = DnsType.Plain)
            } else {
                getDNSDetails(this, customDns != null, customDns).getOrThrow()
            }
        // The ApexGuard build disables the stock ControlD native runtime. Never
        // advertise a resolver that has no listener or silently replace a custom
        // encrypted resolver selected by the user with plaintext DNS.
        check(dns.type != DnsType.Proxy) { "Encrypted DNS runtime unavailable" }
        proxyDNSManager.dnsDetails = dns
        proxyDNSManager.startControlDIfRequired()
        val dnsProxyPort = if (dns.type == DnsType.Proxy) proxyDNSManager.getListenPort() else null
        val resolver =
            when (dns.type) {
                DnsType.Proxy -> "198.18.0.2"
                DnsType.Plain -> requireNotNull(dns.ip)
                DnsType.Tunnel -> "1.1.1.1"
            }
        val protectedDialer = ProtectedDialer(scope, endpoint, grant.port) { protect(it) }.also { dialer = it }
        val socksPort = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }
        val socksUser = UUID.randomUUID().toString()
        val socksPassword = UUID.randomUUID().toString()
        go.Seq.setContext(applicationContext)
        val xudpKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        Libv2ray.initCoreEnv(filesDir.absolutePath, Base64.getUrlEncoder().withoutPadding().encodeToString(xudpKey))
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
        controller.startLoop(
            XrayConfig.create(
                grant,
                requireNotNull(endpoint.hostAddress),
                socksPort,
                socksUser,
                socksPassword,
                protectedDialer.port,
                protectedDialer.username,
                protectedDialer.password,
                dnsProxyPort,
            ),
            0,
        )
        check(controller.isRunning)
        XrayDiagnostics.phase("core_ready")
        XrayDiagnostics.attach({ controller.measureDelay("https://api.ipify.org") }, null)
        coroutineContext.ensureActive()
        check(XrayRuntime.isCurrent(token))
        if (preferencesHelper.splitTunnelToggle) {
            excludedIpHolder.loadCachedIps()
        } else {
            // Saved destination exclusions must stop bypassing when split tunneling is disabled.
            excludedIpHolder.clear()
        }
        val builder =
            Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(1500)
                .addAddress("198.18.0.1", 30)
                .addAddress("fd00:198:18::1", 126)
                .addDnsServer(resolver)
        XrayRoutes
            .includingInternetExcept(if (preferencesHelper.lanByPass) localRoutes() else emptyList())
            .forEach { builder.addRoute(it.address, it.prefix) }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        applyApps(builder)
        excludedIpHolder.applyExcludedRoutes(builder)
        val descriptor = checkNotNull(builder.establish()).also { tun = it }
        val file = File(filesDir, "xray-tunnel.yaml").also { configFile = it }
        file.writeText(XrayConfig.hev(socksPort, socksUser, socksPassword))
        check(TProxyService.TProxyStartService(file.absolutePath, descriptor.fd))
        hevStarted = true
        // JNI starts a thread asynchronously; allow config parsing failure to surface.
        delay(200)
        check(TProxyService.TProxyIsRunning() && controller.isRunning)
        XrayDiagnostics.phase("tun_ready")
        XrayDiagnostics.attach({ controller.measureDelay("https://api.ipify.org") }, { TProxyService.TProxyGetStats() })
        coroutineContext.ensureActive()
        check(!destroying)
        check(XrayRuntime.isCurrent(token))
        XrayRuntime.publish(XrayRuntimeState.Started, token)
        monitorJob =
            scope.launch {
                while (true) {
                    delay(2_000)
                    if (!TProxyService.TProxyIsRunning() || !controller.isRunning) {
                        XrayRuntime.publish(XrayRuntimeState.Failed("VPN tunnel stopped"), token)
                        requestStop()
                        break
                    }
                }
            }
    }

    private fun localRoutes(): List<XrayRoutes.Route> {
        val connectivity = getSystemService(ConnectivityManager::class.java)
        val routes =
            mutableListOf(
                XrayRoutes.Route(InetAddress.getByName("224.0.0.0"), 24),
                XrayRoutes.Route(InetAddress.getByName("255.255.255.255"), 32),
            )
        connectivity.allNetworks.forEach { network ->
            val caps = connectivity.getNetworkCapabilities(network) ?: return@forEach
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@forEach
            connectivity.getLinkProperties(network)?.routes?.filter { !it.isDefaultRoute && !it.hasGateway() }?.forEach { route ->
                routes.add(XrayRoutes.Route(route.destination.address, route.destination.prefixLength))
            }
        }
        return routes.distinct()
    }

    private fun applyApps(builder: Builder) {
        preferencesHelper.lastConnectedUsingSplit = preferencesHelper.splitTunnelToggle
        if (!preferencesHelper.splitTunnelToggle) return
        val inclusive = preferencesHelper.splitRoutingMode == PreferencesKeyConstants.INCLUSIVE_MODE
        // An empty inclusive set must never silently become a VPN for every app.
        // Include our UID for connectivity verification and for ctrld DNS upstreams.
        if (inclusive) builder.addAllowedApplication(packageName)
        preferencesHelper.installedApps.distinct().filter { it != packageName }.forEach { app ->
            try {
                if (inclusive) builder.addAllowedApplication(app) else builder.addDisallowedApplication(app)
            } catch (_: PackageManager.NameNotFoundException) {
                // Stale selections from uninstalled apps are ignored, as with stock backends.
            }
        }
    }

    private suspend fun cleanup() {
        XrayDiagnostics.phase("cleanup_begin")
        XrayDiagnostics.attach(null, null)
        monitorJob?.cancel()
        monitorJob = null
        XrayDiagnostics.phase("cleanup_hev")
        if (hevStarted) runCatching { TProxyService.TProxyStopService() }
        hevStarted = false
        XrayDiagnostics.phase("cleanup_core")
        runCatching { core?.stopLoop() }
        core = null
        XrayDiagnostics.phase("cleanup_dialer")
        runCatching { dialer?.close() }
        dialer = null
        XrayDiagnostics.phase("cleanup_tun")
        runCatching { tun?.close() }
        tun = null
        configFile?.delete()
        configFile = null
        runCatching { proxyDNSManager.stopControlD() }
        XrayDiagnostics.phase("cleanup_complete")
    }

    override fun onRevoke() {
        XrayRuntime.publish(XrayRuntimeState.Failed("VPN permission revoked"), requestToken)
        requestStop()
    }

    @Synchronized private fun requestStop() {
        if (stopJob != null) return
        destroying = true
        XrayDiagnostics.phase("stop_requested")
        startJob?.cancel()
        stopJob =
            scope.launch {
                lifecycle.withLock { cleanup() }
                // Closing the TUN releases Android's system binding. onDestroy then
                // confirms cleanup and publishes Stopped before a successor starts.
                stopSelf()
            }
    }

    override fun onDestroy() {
        destroying = true
        startJob?.cancel()
        scope.launch {
            lifecycle.withLock { cleanup() }
            XrayRuntime.serviceCleanedUp(runtimeOwner, requestToken)
            scope.cancel()
        }
        notificationBuilder.cancelNotification(NotificationConstants.SERVICE_NOTIFICATION_ID)
        super.onDestroy()
    }

    companion object {
        const val START = "com.windscribe.vpn.XRAY_START"
        const val REQUEST_TOKEN = "request-token"
    }
}
