package com.windscribe.vpn.backend.utils

import com.windscribe.vpn.Windscribe
import com.windscribe.vpn.api.apexguard.ApexApiException
import com.windscribe.vpn.api.apexguard.ApexEndpoint
import com.windscribe.vpn.api.apexguard.ApexGrant
import com.windscribe.vpn.api.apexguard.ApexGuardService
import com.windscribe.vpn.api.apexguard.ApexVless
import com.windscribe.vpn.apppreference.PreferencesHelper
import com.windscribe.vpn.autoconnection.ProtocolConnectionStatus
import com.windscribe.vpn.autoconnection.ProtocolInformation
import com.windscribe.vpn.backend.Util
import com.windscribe.vpn.backend.VPNState
import com.windscribe.vpn.backend.VpnBackendHolder
import com.windscribe.vpn.backend.xray.XrayTunnelConfig
import com.windscribe.vpn.localdatabase.LocalDbInterface
import com.windscribe.vpn.repository.LocationRepository
import com.windscribe.vpn.serverlist.entity.Datacenter
import com.windscribe.vpn.serverlist.entity.DatacenterAndLocation
import com.windscribe.vpn.state.DeviceStateManager
import com.windscribe.vpn.state.VPNConnectionStateManager
import io.mockk.Runs
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkObject
import io.mockk.verify
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import java.util.UUID

@OptIn(ExperimentalCoroutinesApi::class)
class ApexGuardConnectionTest {
    private val preferences = mockk<PreferencesHelper>(relaxed = true)
    private val api = mockk<ApexGuardService>(relaxed = true)
    private val creator = mockk<VPNProfileCreator>(relaxed = true)
    private val stateManager = mockk<VPNConnectionStateManager>(relaxed = true)
    private val holder = mockk<VpnBackendHolder>(relaxed = true)
    private val locations = mockk<LocationRepository>(relaxed = true)
    private val database = mockk<LocalDbInterface>(relaxed = true)
    private val deviceStateManager = mockk<DeviceStateManager>(relaxed = true)
    private var launched: ProtocolInformation? = null
    private val states = MutableStateFlow(VPNState(VPNState.Status.Disconnected))
    private val grantStore = ApexGuardGrantStore()

    @Before fun setup() {
        Windscribe.appContext = mockk(relaxed = true)
        mockkObject(Util)
        every { Util.saveProfile(any()) } returns "profile"
        every { Util.saveSelectedLocation(any()) } just Runs
        every { Util.clearProfile() } just Runs
        every { preferences.selectedCity } returns 7
        every { api.authenticated } returns MutableStateFlow(true)
        every { holder.activeBackend } returns null
        every { deviceStateManager.isCurrentNetworkWhitelisted } returns MutableStateFlow(false)
        every { deviceStateManager.getCurrentNetworkName() } returns null
        every { stateManager.state } returns states
        every { stateManager.setState(any(), any()) } answers { states.value = firstArg() }
        coEvery { locations.updateLocation() } returns 7
        every { database.getDatacenterAndLocation(7) } returns
            DatacenterAndLocation().apply {
                datacenter =
                    Datacenter().apply {
                        id = 7
                        nodeName = "City"
                        nickName = "City"
                        coordinates = "48.8566,2.3522"
                    }
            }
    }

    @After fun cleanup() {
        unmockkObject(Util)
    }

    private fun TestScope.controller() =
        object : WindVpnController(
            this,
            preferences,
            creator,
            stateManager,
            holder,
            locations,
            mockk(relaxed = true),
            mockk(relaxed = true),
            mockk(relaxed = true),
            mockk(relaxed = true),
            database,
            deviceStateManager,
            mockk(relaxed = true),
            api,
            grantStore,
        ) {
            override suspend fun launchVPNService(
                protocolInformation: ProtocolInformation,
                connectionId: UUID,
            ) {
                launched = protocolInformation
            }
        }

    private fun protocol(name: String) = ProtocolInformation(name, "443", "", ProtocolConnectionStatus.Disconnected)

    private fun vless() =
        ApexVless(
            "00000000-0000-4000-8000-000000000001",
            "vpn.example",
            8443,
            "raw",
            "vpn.example",
            "key",
            "",
            "chrome",
            "/",
            "",
            "",
            false,
        )

    @Test fun `server grant selects Xray even when the requested protocol was IKEv2`() =
        runTest {
            val link = vless()
            coEvery { api.connect(7, "ikev2", false) } returns ApexGrant("xray", "", "", emptyList(), "ABC", link)
            controller().connect(protocolInformation = protocol("ikev2"))
            assertEquals("xray", launched?.protocol)
            assertEquals("8443", launched?.port)
            verify { Util.saveProfile(match { it is XrayTunnelConfig && it.vless == link }) }
            verify { Util.saveSelectedLocation(match { it.lat == "48.8566" && it.lang == "2.3522" }) }
            verify(exactly = 0) { creator.createIkEV2Profile(any(), any(), any(), any()) }
        }

    @Test fun `IKE fallback uses grant credentials and domain identity rather than catalog addresses`() =
        runTest {
            coEvery { api.connect(7, "xray", false) } returns
                ApexGrant("ikev2", "grant-user", "grant-pass", listOf(ApexEndpoint("gateway.example", "198.51.100.4")), "ABC", null)
            controller().connect(protocolInformation = protocol("xray"))
            assertEquals("ikev2", launched?.protocol)
            verify {
                creator.createIkEV2Profile(
                    match { it.lat == "48.8566" && it.lang == "2.3522" },
                    match { it.ikev2Ip == "198.51.100.4" && it.hostName == "gateway.example" },
                    match {
                        it.protocol ==
                            "ikev2"
                    },
                    "grant-user" to "grant-pass",
                )
            }
        }

    @Test fun `failed grant keeps connection ID in terminal state so automatic connection can finish`() =
        runTest {
            val id = UUID.randomUUID()
            coEvery { api.connect(7, "ikev2", false) } throws ApexApiException("network_error")
            controller().connect(connectionId = id, protocolInformation = protocol("ikev2"))
            runCurrent()
            assertEquals(VPNState.Status.Disconnected, states.value.status)
            assertEquals(id, states.value.connectionId)
            assertNull(launched)
        }

    @Test fun `missing malformed or out of range catalog coordinates disable GPS metadata`() =
        runTest {
            val savedLocations = mutableListOf<LastSelectedLocation>()
            every { Util.saveSelectedLocation(capture(savedLocations)) } just Runs
            coEvery { api.connect(7, "xray", false) } returns ApexGrant("xray", "", "", emptyList(), "ABC", vless())
            val city = database.getDatacenterAndLocation(7)!!.datacenter
            for (coordinates in listOf(null, "", "48.8", "48.8,2.3,1", "NaN,2.3", "48.8,Infinity", "91,2.3", "48.8,-181")) {
                city.coordinates = coordinates
                controller().connect(protocolInformation = protocol("xray"))
                assertEquals("xray", launched?.protocol)
                assertNull(savedLocations.last().lat)
                assertNull(savedLocations.last().lang)
            }
        }

    @Test fun `all sibling endpoints use one remote grant in original order`() =
        runTest {
            val endpoints = (1..3).map { ApexEndpoint("gateway$it.example", "198.51.100.$it") }
            val parameters = mutableListOf<VPNParameters>()
            every { creator.createIkEV2Profile(any(), capture(parameters), any(), any()) } returns "profile"
            coEvery { api.connect(7, "ikev2", false) } returns ApexGrant("ikev2", "user", "pass", endpoints, "ABC", null)
            val controller = controller()
            for (attempt in endpoints.indices) {
                controller.connect(protocolInformation = protocol("ikev2"), attempt = attempt)
                assertEquals(attempt < endpoints.lastIndex, controller.canRetryApexGuardEndpoint(attempt))
            }
            assertEquals(endpoints.map { it.ip }, parameters.map { it.ikev2Ip })
            coVerify(exactly = 1) { api.connect(any(), any(), any()) }
        }

    @Test fun `disconnect while grant is pending cannot install or launch the stale tunnel`() =
        runTest {
            val grant = CompletableDeferred<ApexGrant>()
            coEvery { api.connect(7, "xray", false) } coAnswers { grant.await() }
            val controller = controller()
            val pending = launch { controller.connect(protocolInformation = protocol("xray")) }
            runCurrent()
            controller.disconnectAsync()
            runCurrent()
            grant.complete(ApexGrant("xray", "", "", emptyList(), "ABC", vless()))
            pending.join()
            runCurrent()
            assertNull(launched)
            verify(exactly = 0) { Util.saveProfile(any()) }
            coVerify { api.disconnect() }
        }
}
