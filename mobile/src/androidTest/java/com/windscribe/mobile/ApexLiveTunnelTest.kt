package com.windscribe.mobile

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.view.WindowManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.windscribe.mobile.ui.AppStartActivity
import com.windscribe.vpn.Windscribe.Companion.appContext
import com.windscribe.vpn.apppreference.PreferencesHelper
import com.windscribe.vpn.apppreference.PreferencesKeyConstants
import com.windscribe.vpn.autoconnection.ProtocolConnectionStatus
import com.windscribe.vpn.autoconnection.ProtocolInformation
import com.windscribe.vpn.backend.VPNState
import com.windscribe.vpn.backend.utils.ExcludedIpHolder
import com.windscribe.vpn.backend.utils.WindVpnController
import com.windscribe.vpn.backend.xray.XrayDiagnostics
import com.windscribe.vpn.backend.xray.XrayRuntime
import com.windscribe.vpn.backend.xray.XrayRuntimeState
import com.windscribe.vpn.localdatabase.tables.ExcludedIpDomain
import com.windscribe.vpn.repository.LocationRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.FileInputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.util.UUID

/**
 * Opt-in real-account test. Install :networkprobe:assembleDebug first, grant Android VPN
 * permission once, and pass -e runLiveTunnelTests true to AndroidJUnitRunner.
 * The probe has another UID and uses normal system routing, so this measures routing
 * rather than merely inspecting the selected-app list in a generated configuration.
 * Add -e routingCases extended for destination/cache/app combinations. Optional
 * -e lanIp <RFC1918 address> -e lanPort <TCP nonce echo port> enables LAN assertions.
 */
@RunWith(AndroidJUnit4::class)
class ApexLiveTunnelTest {
    private data class Mode(
        val name: String,
        val enabled: Boolean,
        val inclusive: Boolean,
        val selected: Boolean,
        val tunneled: Boolean,
        val destination: Destination = Destination.NONE,
        val lanBypass: Boolean? = null,
    )

    private enum class Destination {
        NONE,
        IP,
        PREFIX32,
        PREFIX24,
        HOSTNAME,
        HOSTNAME_EMPTY,
        HOSTNAME_STALE,
        HOSTNAME_REFRESH,
    }

    private data class Probe(
        val ip: String,
        val uid: Int,
    )

    @Test fun realIkev2AndXrayApplyUidSplitRouting() =
        runBlocking {
            val arguments = InstrumentationRegistry.getArguments()
            assumeTrue("Live account/network test is opt-in", arguments.getString("runLiveTunnelTests") == "true")
            val instrumentation = InstrumentationRegistry.getInstrumentation()
            val context = instrumentation.targetContext
            val preferences = appContext.preference
            val snapshot = PreferenceSnapshot(preferences)
            var restoreScreen: (() -> Unit)? = null
            try {
                // Prevent stock foreground/network observers racing the explicit test attempts.
                appContext.preference.globalUserConnectionPreference = false
                appContext.preference.autoConnect = false
                val activity =
                    instrumentation.startActivitySync(
                        Intent(context, AppStartActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    ) as AppStartActivity
                val keptAwake = activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON != 0
                instrumentation.runOnMainSync { activity.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON) }
                restoreScreen = {
                    instrumentation.runOnMainSync {
                        if (!keptAwake) activity.window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                    }
                }
                instrumentation.waitForIdleSync()
                val service = activity.apexGuardService
                assertTrue("Sign in through the stock app before running the live test", service.authenticated.value)
                assertNull("Grant Android VPN permission once before the live test", VpnService.prepare(context))
                val probeUid = context.packageManager.getApplicationInfo(PROBE_PACKAGE, 0).uid
                assertNotEquals("Split probe must use another application UID", Process.myUid(), probeUid)
                assertTrue(
                    "Destination exclusions must be empty for an isolated route test",
                    appContext.localDbInterface.getAllExcludedIpsDomains().isEmpty(),
                )
                val controller = appContext.vpnController
                // Reuse the already-generated production graph, without an androidTest-only Hilt entrypoint.
                val locations =
                    WindVpnController::class.java.getDeclaredField("locationRepository").let {
                        it.isAccessible = true
                        it.get(controller) as LocationRepository
                    }
                val excludedIpHolder =
                    WindVpnController::class.java.getDeclaredField("excludedIpHolder").let {
                        it.isAccessible = true
                        it.get(controller) as ExcludedIpHolder
                    }
                val insertedEntries = mutableListOf<ExcludedIpDomain>()
                val protocols = arguments.getString("protocols", "ikev2,xray").split(',')
                require(protocols.isNotEmpty() && protocols.all { it == "ikev2" || it == "xray" })
                val extended = arguments.getString("routingCases") == "extended"
                val lanIp = arguments.getString("lanIp")
                val lanPort = arguments.getString("lanPort")?.toIntOrNull()
                require((lanIp == null && lanPort == null) || (lanIp != null && lanPort != null && lanPort in 1..65535))
                if (lanIp != null) require(isPrivateIpv4(lanIp)) { "lanIp must be a literal RFC1918 IPv4 address" }
                val modes =
                    (
                        listOf(
                            Mode("full", false, false, false, true),
                            Mode("exclusive", true, false, true, false),
                            Mode("inclusive", true, true, true, true),
                            Mode("exclusive-empty", true, false, false, true),
                            Mode("inclusive-empty", true, true, false, false),
                        ) + if (extended) extendedModes(lanIp != null) else emptyList()
                    ).filter { arguments.getString("modes")?.split(',')?.contains(it.name) != false }
                require(modes.isNotEmpty())
                try {
                    preferences.autoConnect = false
                    preferences.globalUserConnectionPreference = false
                    preferences.connectionMode = PreferencesKeyConstants.CONNECTION_MODE_MANUAL
                    preferences.isConnectingToConfigured = false
                    preferences.isConnectingToStaticIp = false
                    preferences.isDecoyTrafficOn = false
                    preferences.lanByPass = false
                    preferences.dnsMode = PreferencesKeyConstants.DNS_MODE_ROBERT
                    stop(controller)
                    val probeIp =
                        withContext(Dispatchers.IO) {
                            InetAddress
                                .getAllByName(PROBE_HOST)
                                .filterIsInstance<Inet4Address>()
                                .first()
                                .hostAddress!!
                        }
                    val physical = withTimeout(40_000) { service.myIp(physical = true) }
                    val baseline = probe(probeIp)
                    assertEquals("Probe baseline must use the physical network", physical, baseline.ip)
                    assertEquals(probeUid, baseline.uid)
                    if (lanIp != null) {
                        assertTrue("LAN target must be reachable before connecting", probeLan(lanIp, requireNotNull(lanPort)))
                    }
                    if (extended &&
                        lanIp == null
                    ) {
                        report("all", "lan-bypass", "skipped: supply lanIp and lanPort for a real listening LAN endpoint")
                    }
                    val catalog = withTimeout(40_000) { service.cities() }
                    val installed =
                        appContext.localDbInterface
                            .getDatacentersAsync()
                            .map { it.id }
                            .toSet()
                    val requestedCity = arguments.getString("cityId")?.toIntOrNull() ?: snapshot.city
                    val city =
                        catalog.firstOrNull { it.id == requestedCity && it.id in installed }
                            ?: catalog.firstOrNull { it.id in installed }
                            ?: error("Open the stock locations screen and wait for the catalog before this test")
                    locations.setSelectedCity(city.id)
                    withTimeout(10_000) { locations.selectedCity.first { it == city.id } }
                    for (protocol in protocols) {
                        for (mode in modes) {
                            if (mode.destination != Destination.NONE && Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                                report(protocol, mode.name, "skipped: destination exclusion requires Android 13+")
                                continue
                            }
                            // Resolve hostnames on the physical network and isolate every destination row.
                            if (mode.destination != Destination.NONE || insertedEntries.isNotEmpty()) stop(controller)
                            insertedEntries.forEach { appContext.localDbInterface.deleteExcludedIpDomain(it) }
                            insertedEntries.clear()
                            excludedIpHolder.loadCachedIps()
                            val destinationIp = prepareDestination(mode.destination, probeIp, excludedIpHolder, insertedEntries)
                            if (destinationIp != probeIp) {
                                assertEquals(
                                    "Resolved hostname target must work on the physical network",
                                    physical,
                                    probe(destinationIp).ip,
                                )
                            }
                            preferences.splitTunnelToggle = mode.enabled
                            preferences.splitRoutingMode =
                                if (mode.inclusive) PreferencesKeyConstants.INCLUSIVE_MODE else PreferencesKeyConstants.EXCLUSIVE_MODE
                            preferences.installedApps = if (mode.selected) listOf(PROBE_PACKAGE) else emptyList()
                            preferences.lanByPass = mode.lanBypass ?: false
                            preferences.savedProtocol = protocol
                            val id = UUID.randomUUID()
                            // connect handles native teardown and /v2/reconnect between mode changes.
                            withTimeout(120_000) {
                                controller.connect(
                                    id,
                                    ProtocolInformation(
                                        protocol,
                                        if (protocol ==
                                            "ikev2"
                                        ) {
                                            "500"
                                        } else {
                                            "443"
                                        },
                                        "",
                                        ProtocolConnectionStatus.Disconnected,
                                    ),
                                )
                                if (protocol == "xray" && arguments.getString("debugXray") == "true") {
                                    withTimeout(10_000) { XrayRuntime.state.first { it == XrayRuntimeState.Started } }
                                    reportXray("tun_started")
                                    val nativeProbe = runCatching { XrayDiagnostics.probeCore() }.getOrDefault(-1L)
                                    reportXray("after_core_probe", nativeProbe)
                                    delay(2_000)
                                    reportXray("after_dns_wait")
                                }
                                val state =
                                    appContext.vpnConnectionStateManager.state.first {
                                        it.connectionId == id && it.status in setOf(VPNState.Status.Connected, VPNState.Status.Disconnected)
                                    }
                                assertEquals(
                                    "$protocol/${mode.name} failed: ${state.error?.error}",
                                    VPNState.Status.Connected,
                                    state.status,
                                )
                                assertEquals(
                                    "Provider must actually grant the requested native protocol",
                                    protocol,
                                    state.protocolInformation?.protocol,
                                )
                            }
                            val tunnelIp = withTimeout(40_000) { service.myIp(physical = false) }
                            val physicalDuringTunnel = withTimeout(40_000) { service.myIp(physical = true) }
                            assertEquals("Physical route must remain unchanged", physical, physicalDuringTunnel)
                            assertNotEquals("Connected requires a distinct, verified VPN exit", physical, tunnelIp)
                            val observed = probe(destinationIp)
                            assertEquals(probeUid, observed.uid)
                            // Xray exits may use different NAT addresses for different destinations.
                            // Compare the independent HTTPS probe against the stable physical route.
                            if (mode.tunneled) {
                                assertNotEquals("$protocol/${mode.name} probe must leave through VPN", physical, observed.ip)
                            } else {
                                assertEquals("$protocol/${mode.name} probe must bypass VPN", physical, observed.ip)
                            }
                            assertEquals(mode.enabled, preferences.lastConnectedUsingSplit)
                            mode.lanBypass?.let { bypass ->
                                assertEquals(
                                    "$protocol/${mode.name} LAN reachability",
                                    bypass,
                                    probeLan(requireNotNull(lanIp), requireNotNull(lanPort)),
                                )
                            }
                            report(protocol, mode.name, "passed", destinationIp)
                        }
                        // The next protocol also reconnects through the production controller,
                        // exercising teardown before a different native backend takes ownership.
                    }
                } finally {
                    withContext(NonCancellable) {
                        try {
                            stop(controller)
                        } finally {
                            try {
                                insertedEntries.forEach { appContext.localDbInterface.deleteExcludedIpDomain(it) }
                                excludedIpHolder.loadCachedIps()
                            } finally {
                                locations.setSelectedCity(snapshot.city)
                            }
                        }
                    }
                }
            } finally {
                try {
                    withContext(NonCancellable) { snapshot.restore(preferences) }
                } finally {
                    restoreScreen?.invoke()
                }
            }
        }

    private suspend fun stop(controller: WindVpnController) {
        controller.disconnectAsync(error = null)
        withTimeout(35_000) {
            while (controller.vpnBackendHolder.activeBackend?.active == true ||
                appContext.vpnConnectionStateManager.state.value.status != VPNState.Status.Disconnected
            ) {
                delay(100)
            }
            // Let the controller finish the remote disconnect and release its operation mutex.
            delay(250)
        }
    }

    /** Finite routing equivalence classes; arbitrary app sets and destination lists are unbounded. */
    private fun extendedModes(withLan: Boolean): List<Mode> {
        val destinations = listOf(Destination.IP, Destination.PREFIX32, Destination.PREFIX24, Destination.HOSTNAME)
        val modes = mutableListOf<Mode>()
        for (destination in destinations) {
            val label = destination.name.lowercase()
            for (inclusive in listOf(false, true)) {
                for (selected in listOf(false, true)) {
                    val app = if (inclusive) "inclusive" else "exclusive"
                    val selection = if (selected) "selected" else "unselected"
                    modes += Mode("$label-$app-$selection", true, inclusive, selected, false, destination)
                }
            }
        }
        modes += Mode("disabled-saved-exclusive", false, false, true, true, Destination.IP)
        modes += Mode("disabled-saved-inclusive", false, true, true, true, Destination.HOSTNAME)
        modes += Mode("hostname-uncached", true, false, false, true, Destination.HOSTNAME_EMPTY)
        modes += Mode("hostname-stale-cache", true, false, false, false, Destination.HOSTNAME_STALE)
        modes += Mode("hostname-refresh", true, false, false, false, Destination.HOSTNAME_REFRESH)
        if (withLan) {
            modes += Mode("lan-bypass-off", false, false, false, true, lanBypass = false)
            modes += Mode("lan-bypass-on", false, false, false, true, lanBypass = true)
        }
        return modes
    }

    private suspend fun prepareDestination(
        destination: Destination,
        probeIp: String,
        holder: ExcludedIpHolder,
        inserted: MutableList<ExcludedIpDomain>,
    ): String {
        if (destination == Destination.NONE) return probeIp
        val type =
            when (destination) {
                Destination.IP -> ExcludedIpDomain.EntryType.IP
                Destination.PREFIX32, Destination.PREFIX24 -> ExcludedIpDomain.EntryType.IP_RANGE
                else -> ExcludedIpDomain.EntryType.HOSTNAME
            }
        val value =
            when (destination) {
                Destination.IP -> probeIp
                Destination.PREFIX32 -> "$probeIp/32"
                Destination.PREFIX24 -> "${probeIp.substringBeforeLast('.')}.0/24"
                else -> PROBE_HOST
            }
        val draft = ExcludedIpDomain(value = value, type = type)
        val entry = draft.copy(id = appContext.localDbInterface.insertExcludedIpDomain(draft))
        inserted += entry // Record immediately, so failed resolution still removes only this test's row.
        if (destination == Destination.HOSTNAME_EMPTY) {
            holder.loadCachedIps()
            return probeIp
        }
        if (destination == Destination.HOSTNAME_REFRESH) {
            appContext.localDbInterface.updateExcludedIpDomain(entry.copy(resolvedIps = "[]", lastResolvedAt = 1L))
            holder.forceRefreshAll()
        } else {
            holder.resolveNewEntry(entry)
        }
        if (type != ExcludedIpDomain.EntryType.HOSTNAME) return probeIp
        var resolved = appContext.localDbInterface.getAllExcludedIpsDomains().single { it.id == entry.id }
        assertNull("Stock hostname resolver failed", resolved.resolutionError)
        val cached = JSONArray(requireNotNull(resolved.resolvedIps) { "Stock hostname resolver did not populate its cache" })
        assertTrue("Hostname cache must contain an IPv4 destination", cached.length() > 0)
        assertTrue("Hostname must record successful resolution", (resolved.lastResolvedAt ?: 0L) > 1L)
        if (destination == Destination.HOSTNAME_STALE) {
            resolved = resolved.copy(lastResolvedAt = 1L)
            appContext.localDbInterface.updateExcludedIpDomain(resolved)
            holder.loadCachedIps()
            assertEquals(
                "Loading a stale cache must preserve its timestamp",
                1L,
                appContext.localDbInterface
                    .getAllExcludedIpsDomains()
                    .single()
                    .lastResolvedAt,
            )
        }
        // Pin to an address actually produced by the stock resolver, avoiding CDN answer drift.
        return cached.getString(0)
    }

    private fun isPrivateIpv4(value: String): Boolean {
        val octets = value.split('.').map { it.toIntOrNull() ?: return false }
        if (octets.size != 4 || octets.any { it !in 0..255 } || value.any { !it.isDigit() && it != '.' }) return false
        return octets[0] == 10 || (octets[0] == 172 && octets[1] in 16..31) || (octets[0] == 192 && octets[1] == 168)
    }

    private suspend fun probeLan(
        ip: String,
        port: Int,
    ): Boolean =
        withContext(Dispatchers.IO) {
            require(isPrivateIpv4(ip) && port in 1..65535)
            val id = UUID.randomUUID().toString()
            val command =
                "timeout 15s am instrument -w -r -e probe_id $id -e lan_ip $ip -e lan_port $port " +
                    "$PROBE_PACKAGE/.NetworkProbeInstrumentation"
            val output =
                InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(command).use { descriptor ->
                    FileInputStream(descriptor.fileDescriptor).bufferedReader().use { it.readText() }
                }
            assertTrue("LAN probe did not return its identity: $output", output.contains("INSTRUMENTATION_RESULT: probe_id=$id"))
            assertTrue("LAN probe failed: $output", !output.contains("INSTRUMENTATION_RESULT: probe_error="))
            Regex("""(?m)^INSTRUMENTATION_RESULT: lan_reachable=(true|false)\s*$""")
                .find(output)
                ?.groupValues
                ?.get(1)
                ?.toBooleanStrict()
                ?: error("LAN probe did not return reachability: $output")
        }

    private suspend fun probe(destinationIp: String): Probe =
        withContext(Dispatchers.IO) {
            val id = UUID.randomUUID().toString()
            val command =
                "timeout 45s am instrument -w -r -e probe_id $id -e destination_ipv4 $destinationIp " +
                    "$PROBE_PACKAGE/.NetworkProbeInstrumentation"
            val output =
                InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(command).use { descriptor ->
                    FileInputStream(descriptor.fileDescriptor).bufferedReader().use { it.readText() }
                }

            fun value(key: String) =
                Regex("(?m)^INSTRUMENTATION_RESULT: $key=(.*)$")
                    .find(output)
                    ?.groupValues
                    ?.get(1)
                    ?.trim()
            assertEquals("Separate-UID probe did not return its request identity", id, value("probe_id"))
            assertNull("Separate-UID HTTPS probe failed", value("probe_error"))
            assertEquals("Probe must connect to the exact excluded destination", destinationIp, value("destination_ipv4"))
            val ip = value("exit_ip") ?: error("Separate-UID HTTPS probe returned no address")
            assertTrue("Probe must return IPv4", ip.matches(Regex("""^\d{1,3}(?:\.\d{1,3}){3}$""")))
            Probe(ip, value("probe_uid")?.toIntOrNull() ?: error("Probe returned no UID"))
        }

    private fun report(
        protocol: String,
        mode: String,
        result: String,
        destinationIp: String? = null,
    ) {
        InstrumentationRegistry.getInstrumentation().sendStatus(
            2,
            Bundle().apply {
                putString("live_protocol", protocol)
                putString("live_split_mode", mode)
                putString("live_result", result)
                destinationIp?.let { putString("live_destination_ipv4", it) }
            },
        )
    }

    private fun reportXray(
        stage: String,
        nativeDelay: Long = -1L,
    ) {
        val snapshot = XrayDiagnostics.snapshot()
        InstrumentationRegistry.getInstrumentation().sendStatus(
            2,
            Bundle().apply {
                putString("xray_debug_stage", stage)
                putString("xray_phase", snapshot.phase)
                putString("xray_failure", snapshot.lastFailure)
                putLong("xray_core_probe_delay_ms", nativeDelay)
                snapshot.counters.forEach { (key, count) -> putLong("xray_$key", count) }
                snapshot.tunStats.forEachIndexed { index, count -> putLong("xray_tun_stat_$index", count) }
            },
        )
    }

    private class PreferenceSnapshot(
        preferences: PreferencesHelper,
    ) {
        val city = preferences.selectedCity
        private val autoConnect = preferences.autoConnect
        private val userConnection = preferences.globalUserConnectionPreference
        private val connectionMode = preferences.connectionMode
        private val savedProtocol = preferences.savedProtocol
        private val splitToggle = preferences.splitTunnelToggle
        private val splitMode = preferences.splitRoutingMode
        private val apps = preferences.installedApps.toList()
        private val configured = preferences.isConnectingToConfigured
        private val static = preferences.isConnectingToStaticIp
        private val decoy = preferences.isDecoyTrafficOn
        private val lanBypass = preferences.lanByPass
        private val dnsMode = preferences.dnsMode
        private val selectedProtocol = preferences.selectedProtocol
        private val selectedPort = preferences.selectedPort
        private val selectedIp = preferences.selectedIp
        private val selectedProtocolType = preferences.selectedProtocolType
        private val lastSplit = preferences.lastConnectedUsingSplit

        fun restore(preferences: PreferencesHelper) {
            preferences.autoConnect = autoConnect
            preferences.globalUserConnectionPreference = userConnection
            preferences.connectionMode = connectionMode
            preferences.savedProtocol = savedProtocol
            preferences.splitTunnelToggle = splitToggle
            preferences.splitRoutingMode = splitMode
            preferences.installedApps = apps
            preferences.isConnectingToConfigured = configured
            preferences.isConnectingToStaticIp = static
            preferences.isDecoyTrafficOn = decoy
            preferences.lanByPass = lanBypass
            preferences.dnsMode = dnsMode
            preferences.selectedProtocol = selectedProtocol
            preferences.selectedPort = selectedPort
            preferences.selectedIp = selectedIp
            preferences.selectedProtocolType = selectedProtocolType
            preferences.lastConnectedUsingSplit = lastSplit
        }
    }

    private companion object {
        const val PROBE_PACKAGE = "com.apexscribe.networkprobe"
        const val PROBE_HOST = "api.ipify.org"
    }
}
