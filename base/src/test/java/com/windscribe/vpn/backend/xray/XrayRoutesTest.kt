package com.windscribe.vpn.backend.xray

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.net.InetAddress

class XrayRoutesTest {
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
}
