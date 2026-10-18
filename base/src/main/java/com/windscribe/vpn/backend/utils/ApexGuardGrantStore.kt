package com.windscribe.vpn.backend.utils

import com.windscribe.vpn.api.apexguard.ApexGrant
import com.windscribe.vpn.backend.VPNState
import javax.inject.Inject
import javax.inject.Singleton

/** One remote grant owns all of its sequential IKE endpoint attempts. Never persisted. */
@Singleton
class ApexGuardGrantStore
    @Inject
    constructor() {
        private data class Attempt(
            val cityId: Int,
            val requestedProtocol: String,
            val grant: ApexGrant,
            val endpointIndex: Int,
        )

        @Volatile private var current: Attempt? = null

        @Synchronized fun remember(
            cityId: Int,
            requestedProtocol: String,
            grant: ApexGrant,
        ) {
            current = Attempt(cityId, requestedProtocol, grant, 0)
        }

        @Synchronized fun retry(
            cityId: Int,
            requestedProtocol: String,
            endpointIndex: Int,
        ): ApexGrant? {
            val cached = current ?: return null
            if (cached.cityId != cityId ||
                cached.requestedProtocol != requestedProtocol ||
                cached.grant.protocol != "ikev2" ||
                endpointIndex != cached.endpointIndex + 1 ||
                endpointIndex !in cached.grant.endpoints.indices
            ) {
                return null
            }
            current = cached.copy(endpointIndex = endpointIndex)
            return cached.grant
        }

        fun hasNextEndpoint(attempt: Int): Boolean {
            val cached = current ?: return false
            return cached.grant.protocol == "ikev2" && cached.endpointIndex == attempt && attempt < cached.grant.endpoints.lastIndex
        }

        fun retainAfterFailure(error: VPNState.Error?): Boolean {
            val cached = current ?: return false
            return error?.error in
                listOf(
                    VPNState.ErrorType.TimeoutError,
                    VPNState.ErrorType.AuthenticationError,
                    VPNState.ErrorType.ConnectivityTestFailed,
                ) &&
                hasNextEndpoint(cached.endpointIndex)
        }

        @Synchronized fun clear() {
            current = null
        }
    }
