package com.windscribe.vpn.backend.xray

import com.google.gson.Gson
import com.windscribe.vpn.api.apexguard.ApexVless

internal object XrayConfig {
    fun create(
        grant: ApexVless,
        endpoint: String,
        socksPort: Int,
        socksUser: String,
        socksPassword: String,
        dialerPort: Int,
        dialerUser: String,
        dialerPassword: String,
        dnsProxyPort: Int? = null,
    ): String {
        require(grant.transport in setOf("tcp", "raw", "grpc"))
        val stream =
            mutableMapOf<String, Any>(
                "network" to if (grant.transport == "grpc") "grpc" else "raw",
                "security" to "reality",
                "realitySettings" to
                    mapOf(
                        "serverName" to grant.serverName,
                        "fingerprint" to grant.fingerprint,
                        "publicKey" to grant.publicKey,
                        "shortId" to grant.shortId,
                        "spiderX" to grant.spiderX,
                    ),
                "sockopt" to mapOf("dialerProxy" to "protected-dialer"),
            )
        if (grant.transport == "grpc") {
            stream["grpcSettings"] = mapOf("serviceName" to grant.serviceName, "multiMode" to grant.multiMode)
        }
        val outbounds =
            mutableListOf<Map<String, Any>>(
                mapOf(
                    "tag" to "proxy",
                    "protocol" to "vless",
                    "settings" to
                        mapOf(
                            "vnext" to
                                listOf(
                                    mapOf(
                                        "address" to endpoint,
                                        "port" to grant.port,
                                        "users" to listOf(mapOf("id" to grant.uuid, "encryption" to "none", "flow" to grant.flow)),
                                    ),
                                ),
                        ),
                    "streamSettings" to stream,
                ),
                mapOf(
                    "tag" to "protected-dialer",
                    "protocol" to "socks",
                    "settings" to
                        mapOf(
                            "servers" to
                                listOf(
                                    mapOf(
                                        "address" to "127.0.0.1",
                                        "port" to dialerPort,
                                        "users" to listOf(mapOf("user" to dialerUser, "pass" to dialerPassword)),
                                    ),
                                ),
                        ),
                ),
            )
        if (dnsProxyPort != null) {
            outbounds.add(
                mapOf(
                    "tag" to "dns-local",
                    "protocol" to "freedom",
                    "settings" to mapOf("redirect" to "127.0.0.1:$dnsProxyPort"),
                ),
            )
        }
        return Gson().toJson(
            mapOf<String, Any>(
                "log" to mapOf("loglevel" to "none"),
                "inbounds" to
                    listOf(
                        mapOf(
                            "tag" to "tun-socks",
                            "listen" to "127.0.0.1",
                            "port" to socksPort,
                            "protocol" to "socks",
                            "settings" to
                                mapOf(
                                    "auth" to "password",
                                    "accounts" to listOf(mapOf("user" to socksUser, "pass" to socksPassword)),
                                    "udp" to true,
                                    "ip" to "127.0.0.1",
                                ),
                        ),
                    ),
                "outbounds" to outbounds,
                "routing" to
                    mapOf<String, Any>(
                        "domainStrategy" to "AsIs",
                        "rules" to
                            if (dnsProxyPort == null) {
                                emptyList()
                            } else {
                                listOf(
                                    mapOf("type" to "field", "ip" to listOf("198.18.0.2"), "port" to "53", "outboundTag" to "dns-local"),
                                )
                            },
                    ),
            ),
        )
    }

    fun hev(
        port: Int,
        user: String,
        password: String,
    ): String =
        """
        tunnel:
          mtu: 1500
          ipv4: 198.18.0.1
          ipv6: 'fd00:198:18::1'
        socks5:
          address: 127.0.0.1
          port: $port
          username: '$user'
          password: '$password'
          udp: 'udp'
        misc:
          log-level: error
          connect-timeout: 15000
          tcp-read-write-timeout: 300000
          udp-read-write-timeout: 60000
        """.trimIndent()
}
