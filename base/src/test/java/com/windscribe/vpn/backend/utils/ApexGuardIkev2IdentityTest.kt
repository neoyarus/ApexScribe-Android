package com.windscribe.vpn.backend.utils

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ApexGuardIkev2IdentityTest {
    @Test fun `single label under fixed provider namespace uses literal certificate DN and granted transport IP`() {
        for (host in listOf("transit-de-mu-01.net1.ch", "node.net1.ch", "NODE.NET1.CH")) {
            val constraint = ApexGuardIkev2Identity.constraint(host, "198.51.100.4")
            assertEquals("198.51.100.4", constraint.gateway)
            assertEquals("CN=*.net1.ch", constraint.remoteId)
        }
    }

    @Test fun `other DNS namespaces and malformed provider lookalikes keep exact hostname certificate constraint`() {
        for (host in listOf(
            "gateway.example",
            "net1.ch",
            "nested.node.net1.ch",
            "node.net1.ch.evil.example",
            "node-notnet1.ch",
            "node.net1.ch.",
            "-node.net1.ch",
            "node-.net1.ch",
            "*.net1.ch",
            "node.net1.ch,CN=other",
            "node.net1.ch\n",
            "198.51.100.4",
        )) {
            val constraint = ApexGuardIkev2Identity.constraint(host, "198.51.100.4")
            assertEquals(host, constraint.gateway)
            assertNull(constraint.remoteId)
        }
    }
}
