package com.windscribe.vpn.backend.utils

import com.windscribe.vpn.api.apexguard.ApexEndpoint
import com.windscribe.vpn.api.apexguard.ApexGrant
import com.windscribe.vpn.backend.VPNState
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class ApexGuardGrantStoreTest {
    private fun grant() =
        ApexGrant("ikev2", "user", "secret", (1..3).map { ApexEndpoint("gateway$it.example", "198.51.100.$it") }, "ABC", null)

    @Test fun `retry advances sequentially and cannot cross city or requested protocol`() {
        val store = ApexGuardGrantStore()
        val grant = grant()
        store.remember(7, "xray", grant)
        assertNull(store.retry(8, "xray", 1))
        assertNull(store.retry(7, "ikev2", 1))
        assertNull(store.retry(7, "xray", 2))
        assertSame(grant, store.retry(7, "xray", 1))
        assertNull(store.retry(7, "xray", 1))
        assertSame(grant, store.retry(7, "xray", 2))
        assertFalse(store.hasNextEndpoint(2))
    }

    @Test fun `only retryable native failures retain grant and explicit stop clears it`() {
        val store = ApexGuardGrantStore()
        store.remember(7, "ikev2", grant())
        assertTrue(store.retainAfterFailure(VPNState.Error(VPNState.ErrorType.TimeoutError)))
        assertTrue(store.retainAfterFailure(VPNState.Error(VPNState.ErrorType.AuthenticationError)))
        assertFalse(store.retainAfterFailure(VPNState.Error(VPNState.ErrorType.UserDisconnect)))
        assertFalse(store.retainAfterFailure(VPNState.Error(VPNState.ErrorType.GenericError)))
        store.clear()
        assertFalse(store.hasNextEndpoint(0))
        assertNull(store.retry(7, "ikev2", 1))
    }
}
