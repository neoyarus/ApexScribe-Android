package com.windscribe.mobile

import android.content.Intent
import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.windscribe.mobile.ui.AppStartActivity
import com.windscribe.vpn.Windscribe.Companion.appContext
import com.windscribe.vpn.backend.xray.XrayDebugProbe
import com.windscribe.vpn.backend.xray.XrayDiagnostics
import com.windscribe.vpn.backend.xray.XrayTunnelConfig
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Opt in with -e runXrayDiagnostics true. Emits only fixed stages and numeric counts. */
@RunWith(AndroidJUnit4::class)
class XrayLiveDiagnosticTest {
    @Test fun isolateGrantedXrayOutboundWithoutTun() =
        runBlocking {
            val instrumentation = InstrumentationRegistry.getInstrumentation()
            val arguments = InstrumentationRegistry.getArguments()
            assumeTrue(arguments.getString("runXrayDiagnostics") == "true")
            val context = instrumentation.targetContext
            appContext.preference.globalUserConnectionPreference = false
            appContext.preference.autoConnect = false
            val activity =
                instrumentation.startActivitySync(
                    Intent(context, AppStartActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                ) as AppStartActivity
            val service = activity.apexGuardService
            assertTrue("Sign in through the stock app first", service.authenticated.value)
            val cities = withTimeout(40_000) { service.cities() }
            val requested = arguments.getString("cityId")?.toIntOrNull() ?: appContext.preference.selectedCity
            val city = cities.firstOrNull { it.id == requested } ?: cities.first()
            try {
                val grant = withTimeout(40_000) { service.connect(city.id, "xray") }
                assertTrue("Provider did not grant Xray", grant.protocol == "xray" && grant.vless != null)
                val result = withTimeout(40_000) { XrayDebugProbe.standalone(context, XrayTunnelConfig(checkNotNull(grant.vless))) }
                report(result.diagnostics, result.passed, result.delayMillis)
                assertTrue("Standalone native outbound failed; see numeric diagnostic counters", result.passed)
            } finally {
                withContext(NonCancellable) { withTimeout(30_000) { service.disconnect() } }
            }
        }

    @Test fun inspectRunningCoreAndTun() =
        runBlocking {
            assumeTrue(InstrumentationRegistry.getArguments().getString("runXrayDiagnostics") == "true")
            report(XrayDiagnostics.snapshot(), false, -1)
            val elapsed = runCatching { XrayDiagnostics.probeCore() }.getOrDefault(-1)
            report(XrayDiagnostics.snapshot(), elapsed >= 0, elapsed)
        }

    private fun report(
        snapshot: XrayDiagnostics.Snapshot,
        passed: Boolean,
        delay: Long,
    ) {
        InstrumentationRegistry.getInstrumentation().sendStatus(
            2,
            Bundle().apply {
                putString("xray_phase", snapshot.phase)
                putString("xray_failure", snapshot.lastFailure)
                putBoolean("xray_probe_passed", passed)
                putLong("xray_probe_delay_ms", delay)
                snapshot.counters.forEach { (key, count) -> putLong("xray_$key", count) }
                snapshot.tunStats.forEachIndexed { index, count -> putLong("xray_tun_stat_$index", count) }
            },
        )
    }
}
