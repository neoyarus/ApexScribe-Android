package com.windscribe.vpn.backend.xray

import java.math.BigInteger
import java.net.InetAddress

/** CIDR subtraction also supports Android 10–12, before Builder.excludeRoute. */
internal object XrayRoutes {
    data class Route(
        val address: InetAddress,
        val prefix: Int,
    )

    fun includingInternetExcept(excluded: List<Route>): List<Route> {
        var routes = listOf(Route(InetAddress.getByName("0.0.0.0"), 0), Route(InetAddress.getByName("::"), 0))
        for (exclude in excluded) routes = routes.flatMap { subtract(it, exclude) }
        return routes
    }

    private fun subtract(
        route: Route,
        excluded: Route,
    ): List<Route> {
        val bytes = route.address.address
        if (bytes.size != excluded.address.address.size) return listOf(route)
        val bits = bytes.size * 8
        require(excluded.prefix in 0..bits && route.prefix in 0..bits)
        val network = BigInteger(1, bytes)
        val outside = BigInteger(1, excluded.address.address)
        val common = minOf(route.prefix, excluded.prefix)
        if (network.shiftRight(bits - common) != outside.shiftRight(bits - common)) return listOf(route)
        if (excluded.prefix <= route.prefix) return emptyList()
        val next = route.prefix + 1
        val right =
            network.setBit(bits - next).toByteArray().let { value ->
                ByteArray(bytes.size).also { result ->
                    val count = minOf(value.size, result.size)
                    value.copyInto(result, result.size - count, value.size - count)
                }
            }
        return subtract(Route(route.address, next), excluded) + subtract(Route(InetAddress.getByAddress(right), next), excluded)
    }
}
