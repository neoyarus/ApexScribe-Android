package com.windscribe.vpn.backend.xray

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.net.InetAddress

class XrayRoutesTest {
    private fun route(
        address: String,
        prefix: Int,
    ) = XrayRoutes.Route(InetAddress.getByName(address), prefix)

    private fun includes(
        routes: List<XrayRoutes.Route>,
        host: String,
    ): Boolean {
        val address = InetAddress.getByName(host).address
        return routes.any { route ->
            route.address.address.size == address.size &&
                BigInteger(1, route.address.address).shiftRight(address.size * 8 - route.prefix) ==
                BigInteger(1, address).shiftRight(address.size * 8 - route.prefix)
        }
    }

    @Test fun bypassesOnlyConnectedLanAndKeepsPublicAndOtherPrivateTrafficInTunnel() {
        val routes =
            XrayRoutes.includingInternetExcept(
                listOf(
                    XrayRoutes.Route(InetAddress.getByName("192.168.3.0"), 24),
                    XrayRoutes.Route(InetAddress.getByName("fe80::"), 64),
                ),
            )
        assertFalse(includes(routes, "192.168.3.1"))
        assertFalse(includes(routes, "192.168.3.255"))
        assertFalse(includes(routes, "fe80::1"))
        assertTrue(includes(routes, "192.168.4.1"))
        assertTrue(includes(routes, "10.0.0.1"))
        assertTrue(includes(routes, "1.1.1.1"))
        assertTrue(includes(routes, "2606:4700:4700::1111"))
    }

    @Test fun noBypassRoutesCaptureBothFamilies() {
        val routes = XrayRoutes.includingInternetExcept(emptyList())
        assertTrue(includes(routes, "192.168.3.1"))
        assertTrue(includes(routes, "1.1.1.1"))
        assertTrue(includes(routes, "fe80::1"))
        assertTrue(includes(routes, "2606:4700:4700::1111"))
    }

    @Test fun singleHostBypassesKeepAdjacentAddressesInBothFamilies() {
        val routes =
            XrayRoutes.includingInternetExcept(
                listOf(route("192.168.3.1", 32), route("fd00::1", 128)),
            )
        assertFalse(includes(routes, "192.168.3.1"))
        assertTrue(includes(routes, "192.168.3.0"))
        assertTrue(includes(routes, "192.168.3.2"))
        assertFalse(includes(routes, "fd00::1"))
        assertTrue(includes(routes, "fd00::"))
        assertTrue(includes(routes, "fd00::2"))
    }

    @Test fun familyWideBypassPreservesTheOtherFamily() {
        val ipv4Bypass = XrayRoutes.includingInternetExcept(listOf(route("0.0.0.0", 0)))
        assertFalse(includes(ipv4Bypass, "0.0.0.0"))
        assertFalse(includes(ipv4Bypass, "255.255.255.255"))
        assertTrue(includes(ipv4Bypass, "::"))
        assertTrue(includes(ipv4Bypass, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))

        val ipv6Bypass = XrayRoutes.includingInternetExcept(listOf(route("::", 0)))
        assertTrue(includes(ipv6Bypass, "0.0.0.0"))
        assertTrue(includes(ipv6Bypass, "255.255.255.255"))
        assertFalse(includes(ipv6Bypass, "::"))
        assertFalse(includes(ipv6Bypass, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
    }

    @Test fun overlappingAndDuplicateBypassesAreOrderIndependent() {
        val exclusions =
            listOf(
                route("10.0.0.0", 8),
                route("10.1.0.0", 16),
                route("10.0.0.0", 8),
                route("fc00::", 7),
                route("fd00::", 8),
            )
        val routes = XrayRoutes.includingInternetExcept(exclusions)
        val reversed = XrayRoutes.includingInternetExcept(exclusions.reversed())
        listOf("10.0.0.0", "10.1.0.1", "10.255.255.255", "fc00::1", "fdff::1").forEach {
            assertFalse(includes(routes, it))
            assertFalse(includes(reversed, it))
        }
        listOf("9.255.255.255", "11.0.0.0", "fbff::1", "fe00::1").forEach {
            assertTrue(includes(routes, it))
            assertTrue(includes(reversed, it))
        }
    }

    @Test fun adjacentBypassesLeaveNoGapAndDoNotConsumeNeighboringNetworks() {
        val routes =
            XrayRoutes.includingInternetExcept(
                listOf(
                    route("192.168.2.0", 24),
                    route("192.168.3.0", 24),
                    route("fd00::", 127),
                    route("fd00::2", 127),
                ),
            )
        listOf("192.168.2.0", "192.168.2.255", "192.168.3.0", "192.168.3.255", "fd00::", "fd00::3").forEach {
            assertFalse(includes(routes, it))
        }
        listOf("192.168.1.255", "192.168.4.0", "fcff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fd00::4").forEach {
            assertTrue(includes(routes, it))
        }
    }

    @Test fun bypassingBothFamiliesProducesNoTunnelRoutes() {
        assertTrue(XrayRoutes.includingInternetExcept(listOf(route("0.0.0.0", 0), route("::", 0))).isEmpty())
    }
}
