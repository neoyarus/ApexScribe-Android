package com.windscribe.vpn.backend.xray

import com.google.gson.JsonParser
import com.windscribe.vpn.api.apexguard.ApexVless
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class XrayConfigTest {
    private val grant =
        ApexVless(
            "de04add9-5c68-4bab-950c-08cd5320df18",
            "vpn.example.com",
            443,
            "raw",
            "example.com",
            "w6Qe7jmsr3ODd08qpfBC_0hVOmCkhpEFuqNTBFQFwQo",
            "aabb",
            "chrome",
            "/",
            "xtls-rprx-vision",
            "",
            false,
        )

    @Test fun outerTransportMustUseProtectedDialerAndNoDirectFallback() {
        val root =
            JsonParser
                .parseString(
                    XrayConfig.create(grant, "203.0.113.9", 1080, "user", "pass", 1081, "dial", "secret"),
                ).asJsonObject
        val outbounds = root.getAsJsonArray("outbounds")
        assertEquals(2, outbounds.size())
        val proxy = outbounds[0].asJsonObject
        assertEquals("vless", proxy["protocol"].asString)
        assertEquals("protected-dialer", proxy.getAsJsonObject("streamSettings").getAsJsonObject("sockopt")["dialerProxy"].asString)
        val server = proxy.getAsJsonObject("settings").getAsJsonArray("vnext")[0].asJsonObject
        assertEquals("203.0.113.9", server["address"].asString)
        assertEquals("example.com", proxy.getAsJsonObject("streamSettings").getAsJsonObject("realitySettings")["serverName"].asString)
        assertFalse(outbounds.any { it.asJsonObject["protocol"].asString == "freedom" })
        assertEquals("127.0.0.1", root.getAsJsonArray("inbounds")[0].asJsonObject["listen"].asString)
        assertTrue(root.getAsJsonObject("routing").getAsJsonArray("rules").isEmpty)
    }

    @Test fun grpcPreservesGrantSettings() {
        val root =
            JsonParser
                .parseString(
                    XrayConfig.create(
                        grant.copy(transport = "grpc", flow = "", serviceName = "hello/service", multiMode = true),
                        "203.0.113.9",
                        1080,
                        "user",
                        "pass",
                        1081,
                        "dial",
                        "secret",
                    ),
                ).asJsonObject
        val stream = root.getAsJsonArray("outbounds")[0].asJsonObject.getAsJsonObject("streamSettings")
        assertEquals("grpc", stream["network"].asString)
        assertEquals("hello/service", stream.getAsJsonObject("grpcSettings")["serviceName"].asString)
        assertTrue(stream.getAsJsonObject("grpcSettings")["multiMode"].asBoolean)
    }
}
