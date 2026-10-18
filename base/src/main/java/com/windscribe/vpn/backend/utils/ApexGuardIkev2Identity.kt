package com.windscribe.vpn.backend.utils

/**
 * The provider's net1.ch gateways advertise the literal IKE DN CN=*.net1.ch.
 * strongSwan's bundled SAN matcher doesn't interpret wildcards on the certificate
 * side. Limit compatibility to the provider's fixed, single-label DNS namespace
 * and require its exact certificate-backed DN, keeping CA and signature checks.
 * Other namespaces retain the native exact-hostname/SAN authentication path.
 */
internal object ApexGuardIkev2Identity {
    data class Constraint(
        val gateway: String,
        val remoteId: String?,
    )

    private val providerHostname = Regex("""^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.net1\.ch$""", RegexOption.IGNORE_CASE)

    fun constraint(
        hostname: String,
        grantedIp: String,
    ): Constraint =
        if (providerHostname.matches(hostname)) {
            // In strongSwan DN syntax this asterisk is part of the literal CN value.
            // A DN wildcard would require the entire RDN value to be exactly '*'.
            Constraint(grantedIp, "CN=*.net1.ch")
        } else {
            // Omitted remote_id requires gateway to match the authenticated certificate SAN.
            Constraint(hostname, null)
        }
}
