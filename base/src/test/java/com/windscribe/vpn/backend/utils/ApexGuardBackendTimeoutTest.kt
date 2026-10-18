package com.windscribe.vpn.backend.utils

import com.windscribe.vpn.Windscribe
import com.windscribe.vpn.api.apexguard.ApexGuardService
import com.windscribe.vpn.apppreference.PreferencesHelper
import com.windscribe.vpn.backend.Util
import com.windscribe.vpn.backend.VPNState
import com.windscribe.vpn.backend.VpnBackend
import com.windscribe.vpn.backend.ikev2.CharonVpnServiceWrapper
import com.windscribe.vpn.backend.ikev2.IKev2VpnBackend
import com.windscribe.vpn.backend.xray.XrayBackend
import com.windscribe.vpn.backend.xray.XrayRuntime
import com.windscribe.vpn.backend.xray.XrayRuntimeState
import com.windscribe.vpn.state.VPNConnectionStateManager
import io.mockk.Runs
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkObject
import io.mockk.verify
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Test
import java.util.UUID

@OptIn(ExperimentalCoroutinesApi::class)
class ApexGuardBackendTimeoutTest {
    private val preferences = mockk<PreferencesHelper>(relaxed = true)
    private val service = mockk<ApexGuardService>(relaxed = true)
    private val stateManager = mockk<VPNConnectionStateManager>(relaxed = true)
    private val connectionId = UUID.randomUUID()
    private val states = MutableStateFlow(VPNState(VPNState.Status.Connecting, connectionId = connectionId))

    @Before fun setup() {
        Windscribe.appContext = mockk(relaxed = true)
        mockkObject(Util)
        every { Util.clearProfile() } just Runs
        every { stateManager.state } returns states
        every { stateManager.setState(any(), any()) } answers { states.value = firstArg() }
    }

    @After fun cleanup() {
        unmockkObject(Util)
        unmockkObject(XrayRuntime)
    }

    private fun TestScope.expireConnection(backend: VpnBackend) {
        backend.active = true
        backend.connectionId = connectionId
        backend.startConnectionJob()
        runCurrent()
        advanceTimeBy(VpnBackend.CONNECTING_WAIT + 100)
        runCurrent()
        assertFalse(backend.connectionJob!!.isCancelled)
        assertFalse(backend.active)
        assertEquals(VPNState.Status.Disconnected, states.value.status)
        assertEquals(VPNState.ErrorType.TimeoutError, states.value.error?.error)
        coVerify(exactly = 1) { service.disconnect() }
        verify { Util.clearProfile() }
    }

    @Test fun `Xray timeout waits for native shutdown and publishes disconnected`() =
        runTest {
            val runtimeState = MutableStateFlow<XrayRuntimeState>(XrayRuntimeState.Started)
            mockkObject(XrayRuntime)
            every { XrayRuntime.state } returns runtimeState
            every { XrayRuntime.stop(any()) } answers {
                backgroundScope.launch {
                    delay(1)
                    runtimeState.value = XrayRuntimeState.Stopped
                }
                Unit
            }
            val backend =
                XrayBackend(
                    backgroundScope,
                    stateManager,
                    preferences,
                    mockk(relaxed = true),
                    mockk(relaxed = true),
                    mockk(relaxed = true),
                    mockk(relaxed = true),
                    mockk(relaxed = true),
                    mockk(relaxed = true),
                    service,
                    ApexGuardGrantStore(),
                )
            expireConnection(backend)
            verify(exactly = 1) { XrayRuntime.stop(Windscribe.appContext) }
        }

    @Test fun `IKEv2 timeout closes native service and publishes disconnected`() =
        runTest {
            val nativeService = mockk<CharonVpnServiceWrapper>(relaxed = true)
            val backend =
                IKev2VpnBackend(
                    backgroundScope,
                    mockk(relaxed = true),
                    stateManager,
                    preferences,
                    mockk(relaxed = true),
                    mockk(relaxed = true),
                    mockk(relaxed = true),
                    mockk(relaxed = true),
                    mockk(relaxed = true),
                    mockk(relaxed = true),
                    service,
                    ApexGuardGrantStore(),
                )
            backend.service = nativeService
            expireConnection(backend)
            verify(exactly = 1) { nativeService.setNextProfile(null) }
            verify(exactly = 1) { nativeService.close() }
        }
}
