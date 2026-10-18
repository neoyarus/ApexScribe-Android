package com.windscribe.mobile

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.windscribe.mobile.ui.AppStartActivity
import com.windscribe.vpn.Windscribe.Companion.appContext
import com.windscribe.vpn.apppreference.PreferencesHelper
import com.windscribe.vpn.apppreference.PreferencesKeyConstants
import com.windscribe.vpn.autoconnection.ProtocolConnectionStatus
import com.windscribe.vpn.autoconnection.ProtocolInformation
import com.windscribe.vpn.backend.VPNState
import com.windscribe.vpn.backend.utils.WindVpnController
import com.windscribe.vpn.backend.xray.XrayDiagnostics
import com.windscribe.vpn.backend.xray.XrayRuntime
import com.windscribe.vpn.backend.xray.XrayRuntimeState
import com.windscribe.vpn.repository.LocationRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.FileInputStream
import java.util.UUID

/**
 * Opt-in real-account test. Install :networkprobe:assembleDebug first, grant Android VPN
 * permission once, and pass -e runLiveTunnelTests true to AndroidJUnitRunner.
 * The probe has another UID and uses normal system routing, so this measures routing
 * rather than merely inspecting the selected-app list in a generated configuration.
 */
@RunWith(AndroidJUnit4::class)
class ApexLiveTunnelTest {
    private data class Mode(
        val name: String,
        val enabled: Boolean,
        val inclusive: Boolean,
        val selected: Boolean,
        val tunneled: Boolean,
    )

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
            // Prevent stock foreground/network observers racing the explicit test attempts.
            appContext.preference.globalUserConnectionPreference = false
            appContext.preference.autoConnect = false
            val activity =
                instrumentation.startActivitySync(
                    Intent(context, AppStartActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                ) as AppStartActivity
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
            val preferences = appContext.preference
            val snapshot = PreferenceSnapshot(preferences)
            val protocols = arguments.getString("protocols", "ikev2,xray").split(',')
            require(protocols.isNotEmpty() && protocols.all { it == "ikev2" || it == "xray" })
            val modes =
                listOf(
                    Mode("full", false, false, false, true),
                    Mode("exclusive", true, false, true, false),
                    Mode("inclusive", true, true, true, true),
                    Mode("exclusive-empty", true, false, false, true),
                    Mode("inclusive-empty", true, true, false, false),
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
                val physical = withTimeout(40_000) { service.myIp(physical = true) }
                val baseline = probe()
                assertEquals("Probe baseline must use the physical network", physical, baseline.ip)
                assertEquals(probeUid, baseline.uid)
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
                        preferences.splitTunnelToggle = mode.enabled
                        preferences.splitRoutingMode =
                            if (mode.inclusive) PreferencesKeyConstants.INCLUSIVE_MODE else PreferencesKeyConstants.EXCLUSIVE_MODE
                        preferences.installedApps = if (mode.selected) listOf(PROBE_PACKAGE) else emptyList()
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
                            assertEquals("$protocol/${mode.name} failed: ${state.error?.error}", VPNState.Status.Connected, state.status)
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
                        val observed = probe()
                        assertEquals(probeUid, observed.uid)
                        // Xray exits may use different NAT addresses for different destinations.
                        // Compare the independent HTTPS probe against the stable physical route.
                        if (mode.tunneled) {
                            assertNotEquals("$protocol/${mode.name} probe must leave through VPN", physical, observed.ip)
                        } else {
                            assertEquals("$protocol/${mode.name} probe must bypass VPN", physical, observed.ip)
                        }
                        assertEquals(mode.enabled, preferences.lastConnectedUsingSplit)
                        report(protocol, mode.name, "passed")
                    }
                    // The next protocol also reconnects through the production controller,
                    // exercising teardown before a different native backend takes ownership.
                }
            } finally {
                withContext(NonCancellable) {
                    try {
                        stop(controller)
                    } finally {
                        snapshot.restore(preferences)
                        locations.setSelectedCity(snapshot.city)
                    }
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

    private suspend fun probe(): Probe =
        withContext(Dispatchers.IO) {
            val id = UUID.randomUUID().toString()
            val command = "timeout 35s am instrument -w -r -e probe_id $id $PROBE_PACKAGE/.NetworkProbeInstrumentation"
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
            val ip = value("exit_ip") ?: error("Separate-UID HTTPS probe returned no address")
            assertTrue("Probe must return IPv4", ip.matches(Regex("""^\d{1,3}(?:\.\d{1,3}){3}$""")))
            Probe(ip, value("probe_uid")?.toIntOrNull() ?: error("Probe returned no UID"))
        }

    private fun report(
        protocol: String,
        mode: String,
        result: String,
    ) {
        InstrumentationRegistry.getInstrumentation().sendStatus(
            2,
            Bundle().apply {
                putString("live_protocol", protocol)
                putString("live_split_mode", mode)
                putString("live_result", result)
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
    }
}
