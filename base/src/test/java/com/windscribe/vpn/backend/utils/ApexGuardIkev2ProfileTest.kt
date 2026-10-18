package com.windscribe.vpn.backend.utils

import android.text.TextUtils
import com.windscribe.vpn.Windscribe
import com.windscribe.vpn.apppreference.PreferencesHelper
import com.windscribe.vpn.apppreference.PreferencesKeyConstants
import com.windscribe.vpn.autoconnection.ProtocolConnectionStatus
import com.windscribe.vpn.autoconnection.ProtocolInformation
import com.windscribe.vpn.backend.Util
import com.windscribe.vpn.constants.NetworkErrorCodes.ERROR_INVALID_DNS_ADDRESS
import com.windscribe.vpn.exceptions.InvalidVPNConfigException
import io.mockk.Runs
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkObject
import io.mockk.unmockkStatic
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.strongswan.android.data.VpnProfile

class ApexGuardIkev2ProfileTest {
    private val preferences = mockk<PreferencesHelper>(relaxed = true)
    private val savedProfile = slot<Any>()
    private lateinit var creator: VPNProfileCreator

    @Before fun setup() {
        Windscribe.appContext = mockk(relaxed = true)
        every { Windscribe.appContext.packageName } returns "com.apexscribe.android"
        mockkObject(Util)
        every { Util.saveSelectedLocation(any()) } just Runs
        every { Util.saveProfile(capture(savedProfile)) } returns "profile"
        mockkStatic(TextUtils::class)
        every { TextUtils.join(any<CharSequence>(), any<Iterable<*>>()) } answers {
            secondArg<Iterable<*>>().joinToString(firstArg<CharSequence>().toString())
        }
        every { TextUtils.isEmpty(any()) } answers { firstArg<CharSequence?>().isNullOrEmpty() }
        every { preferences.isKeepAliveModeAuto } returns true
        every { preferences.isPackageSizeModeAuto } returns true
        every { preferences.splitTunnelToggle } returns true
        every { preferences.installedApps } returns listOf("com.example.video", "com.apexscribe.android")
        creator = VPNProfileCreator(preferences, mockk(relaxed = true), mockk(relaxed = true), mockk(relaxed = true), mockk(relaxed = true))
    }

    @After fun cleanup() {
        unmockkObject(Util)
        unmockkStatic(TextUtils::class)
    }

    private fun create(hostname: String = "gateway.example"): VpnProfile {
        creator.createIkEV2Profile(
            LastSelectedLocation(7, "City", "City"),
            VPNParameters("198.51.100.4", "", "", "", hostname, "", ""),
            ProtocolInformation("ikev2", "500", "", ProtocolConnectionStatus.Disconnected),
            "grant-user" to "grant-pass",
        )
        return savedProfile.captured as VpnProfile
    }

    @Test fun `inclusive profile uses grant identity and only chosen apps plus verification UID`() {
        every { preferences.splitRoutingMode } returns PreferencesKeyConstants.INCLUSIVE_MODE
        val profile = create()
        assertEquals(VpnProfile.SelectedAppsHandling.SELECTED_APPS_ONLY, profile.selectedAppsHandling)
        assertEquals(setOf("com.example.video", "com.apexscribe.android"), profile.selectedAppsSet)
        assertEquals("gateway.example", profile.gateway)
        assertNull(profile.remoteId)
        assertEquals("ApexGuard", profile.localId)
        assertEquals("grant-user", profile.username)
        assertEquals("grant-pass", profile.password)
        assertNull(profile.certificateAlias)
        assertNull(profile.ikeProposal)
        assertNull(profile.espProposal)
        assertEquals(Integer.valueOf(1400), profile.mtu)
        assertEquals(Integer.valueOf(VpnProfile.SPLIT_TUNNELING_BLOCK_IPV6), profile.splitTunneling)
        verify { preferences.lastConnectedUsingSplit = true }
    }

    @Test fun `known provider wildcard namespace requires exact certificate backed DN at grant IP`() {
        val profile = create("transit-de-mu-01.net1.ch")
        assertEquals("198.51.100.4", profile.gateway)
        assertEquals("CN=*.net1.ch", profile.remoteId)
        assertNull("CA chain verification must remain enabled", profile.certificateAlias)
        assertEquals(0, profile.flags)
    }

    @Test fun `server DN identity uses exact grant hostname certificate constraint through native SAN fallback`() {
        val profile = create()
        assertEquals("gateway.example", profile.gateway)
        assertNull("An explicit IKE ID would reject a valid certificate when the server uses its DN", profile.remoteId)
        assertNull("Certificate validation must use trusted roots", profile.certificateAlias)
        assertEquals(0, profile.flags)
    }

    @Test fun `exclusive profile excludes selected apps and keeps verification UID inside VPN`() {
        every { preferences.splitRoutingMode } returns PreferencesKeyConstants.EXCLUSIVE_MODE
        val profile = create()
        assertEquals(VpnProfile.SelectedAppsHandling.SELECTED_APPS_EXCLUDE, profile.selectedAppsHandling)
        assertEquals(setOf("com.example.video"), profile.selectedAppsSet)
    }

    @Test fun `unsupported encrypted DNS fails before installing an IKE profile`() {
        every { preferences.dnsMode } returns PreferencesKeyConstants.DNS_MODE_CUSTOM
        every { preferences.dnsAddress } returns "https://dns.example/dns-query"
        val failure = assertThrows(InvalidVPNConfigException::class.java) { create() }
        assertEquals(ERROR_INVALID_DNS_ADDRESS, failure.error.code)
        verify(exactly = 0) { Util.saveProfile(any()) }
    }

    @Test fun `empty inclusive selection stays inclusive with only verification UID`() {
        every { preferences.splitRoutingMode } returns PreferencesKeyConstants.INCLUSIVE_MODE
        every { preferences.installedApps } returns emptyList()
        val profile = create()
        assertEquals(VpnProfile.SelectedAppsHandling.SELECTED_APPS_ONLY, profile.selectedAppsHandling)
        assertEquals(setOf("com.apexscribe.android"), profile.selectedAppsSet)
    }
}
