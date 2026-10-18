package com.windscribe.vpn.api.apexguard

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.Base64
import java.util.UUID

class ApexApiException(
    val code: String,
    val status: Int = 0,
) : Exception(code)

class ApexTokens(
    val access: String,
    val refresh: String,
) {
    override fun toString() = "ApexTokens([redacted])"
}

data class ApexCity(
    val country: String,
    val countryCode: String,
    val name: String,
    val code: String,
    val latitude: Double,
    val longitude: Double,
) {
    val countryId: Int get() = ApexContracts.codeId(countryCode)
    val id: Int get() = countryId * 32768 + ApexContracts.codeId(code)
}

data class ApexEndpoint(
    val domain: String,
    val ip: String,
)

data class ApexVless(
    val uuid: String,
    val host: String,
    val port: Int,
    val transport: String,
    val serverName: String,
    val publicKey: String,
    val shortId: String,
    val fingerprint: String,
    val spiderX: String,
    val flow: String,
    val serviceName: String,
    val multiMode: Boolean,
) {
    override fun toString() = "ApexVless([redacted])"
}

class ApexGrant(
    val protocol: String,
    val username: String,
    val password: String,
    val endpoints: List<ApexEndpoint>,
    val cityCode: String,
    val vless: ApexVless?,
) {
    override fun toString() = "ApexGrant($protocol, [redacted])"
}

data class ApexHostedLogin(
    val url: String,
    val origin: String,
)

object ApexContracts {
    private val code = Regex("^[A-Z]{3}$")
    private val label = Regex("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

    fun codeId(value: String): Int = value.fold(0) { result, ch -> (result shl 5) or (ch.code - 'A'.code + 1) }

    fun safeText(
        value: String,
        max: Int,
    ): Boolean = value.length <= max && value.none { it.code < 32 || it.code == 127 }

    fun dnsName(value: String): Boolean =
        value.length in 1..253 &&
            !value.endsWith('.') &&
            value.split('.').size >= 2 &&
            value.any { it.isLetter() } &&
            value.split('.').all { label.matches(it) }

    fun ipv4(value: String): Boolean {
        val parts = value.split('.')
        return parts.size == 4 &&
            parts.all { part -> part.toIntOrNull()?.let { it in 0..255 && it.toString() == part } == true } &&
            parts[0].toInt() !in listOf(0, 127) &&
            parts[0].toInt() < 224
    }

    fun gateway(value: String): Boolean =
        runCatching {
            val uri = URI(value)
            val host = uri.host?.lowercase() ?: return@runCatching false
            uri.scheme == "https" &&
                dnsName(host) &&
                host.endsWith(".apexguard.com") &&
                host != "my.apexguard.com" &&
                uri.userInfo == null &&
                uri.port in listOf(-1, 443) &&
                uri.rawPath in listOf("", "/") &&
                uri.rawQuery == null &&
                uri.rawFragment == null
        }.getOrDefault(false)

    private fun query(uri: URI): Map<String, String> {
        val result = linkedMapOf<String, String>()
        uri.rawQuery?.split('&')?.forEach { field ->
            val pair = field.split('=', limit = 2)
            val name = URLDecoder.decode(pair[0], "UTF-8")
            val value = URLDecoder.decode(pair.getOrElse(1) { "" }, "UTF-8")
            if (result.containsKey(name) && result[name] != value) throw ApexApiException("invalid_link")
            result[name] = value
        }
        return result
    }

    fun hostedLogin(data: JsonObject): ApexHostedLogin {
        try {
            val uri = URI(data.get("auth").asString)
            if (uri.scheme != "https" ||
                uri.host != "my.apexguard.com" ||
                uri.port !in listOf(-1, 443) ||
                uri.userInfo != null ||
                uri.rawFragment != null
            ) {
                throw ApexApiException("invalid_login_link")
            }
            val fields = query(uri).toMutableMap()
            val origin = String(Base64.getDecoder().decode(fields["h"]), Charsets.UTF_8)
            if (!gateway(origin)) throw ApexApiException("invalid_login_link")
            fields["device"] = "mobile"
            fields["redirect_url"] = "apexguard://login"
            val encoded =
                fields.entries.joinToString(
                    "&",
                ) { URLEncoder.encode(it.key, "UTF-8") + "=" + URLEncoder.encode(it.value, "UTF-8") }
            return ApexHostedLogin("https://my.apexguard.com${uri.rawPath.orEmpty()}?$encoded", origin.trimEnd('/'))
        } catch (_: Exception) {
            throw ApexApiException("invalid_login_link")
        }
    }

    fun callbackCode(value: String): String {
        try {
            val uri = URI(value)
            val fields = query(uri)
            val token = fields["exchange_token"].orEmpty()
            if (uri.scheme != "apexguard" ||
                uri.host != "login" ||
                uri.userInfo != null ||
                uri.port != -1 ||
                !uri.rawPath.isNullOrEmpty() ||
                uri.rawFragment != null ||
                fields["status"] != "done" ||
                (fields.containsKey("action") && fields["action"] != "login") ||
                token.isEmpty() ||
                !safeText(token, 8192)
            ) {
                throw ApexApiException("invalid_callback")
            }
            return token
        } catch (_: Exception) {
            throw ApexApiException("invalid_callback")
        }
    }

    fun tokens(data: JsonObject): ApexTokens {
        val access = data.get("access_token")?.asString.orEmpty()
        val refresh = data.get("refresh_token")?.asString.orEmpty()
        if (access.isEmpty() ||
            refresh.isEmpty() ||
            !safeText(access, 32768) ||
            !safeText(refresh, 32768)
        ) {
            throw ApexApiException("invalid_response")
        }
        return ApexTokens(access, refresh)
    }

    fun cities(data: JsonElement): List<ApexCity> {
        if (!data.isJsonArray || data.asJsonArray.size() > 20000) throw ApexApiException("invalid_response")
        val result =
            data.asJsonArray.map { value ->
                val row = value.asJsonObject
                val gps = row.getAsJsonObject("coordinates")
                val city =
                    ApexCity(
                        row["country"].asString,
                        row["country_code"].asString,
                        row["city"].asString,
                        row["code"].asString,
                        gps["lat"].asDouble,
                        gps["lon"].asDouble,
                    )
                if (!code.matches(city.code) ||
                    !code.matches(city.countryCode) ||
                    city.country.isEmpty() ||
                    city.name.isEmpty() ||
                    !safeText(city.country, 256) ||
                    !safeText(city.name, 256) ||
                    !city.latitude.isFinite() ||
                    !city.longitude.isFinite() ||
                    city.latitude !in -90.0..90.0 ||
                    city.longitude !in -180.0..180.0
                ) {
                    throw ApexApiException("invalid_response")
                }
                city
            }
        if (result.map { it.id }.toSet().size != result.size) throw ApexApiException("invalid_response")
        return result
    }

    fun vless(value: String): ApexVless {
        try {
            val uri = URI(value)
            val q = query(uri)
            val uuid = uri.userInfo.orEmpty()
            if (value.length > 16384 ||
                uri.scheme != "vless" ||
                !Regex("^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$").matches(uuid) ||
                UUID.fromString(uuid) == UUID(0, 0) ||
                (!ipv4(uri.host.orEmpty()) && !dnsName(uri.host.orEmpty())) ||
                uri.port !in 1..65535 ||
                uri.rawPath !in listOf(null, "", "/") ||
                q.keys.any { it.equals("allowInsecure", true) } ||
                q.values.any { !safeText(it, 4096) } ||
                q["security"] != "reality"
            ) {
                throw ApexApiException("invalid_link")
            }
            val transport =
                when (val type = q["type"] ?: "tcp") {
                    "tcp" -> "raw"
                    else -> type
                }
            val key = q["pbk"].orEmpty()
            val sid = q["sid"].orEmpty()
            var fp = q["fp"] ?: "chrome"
            if (fp.isEmpty() || fp == "android") fp = "chrome"
            val flow = q["flow"].orEmpty()
            if (transport !in listOf("raw", "grpc") ||
                !dnsName(q["sni"].orEmpty()) ||
                !Regex("^[A-Za-z0-9_-]{43}$").matches(key) ||
                Base64.getUrlDecoder().decode(key).size != 32 ||
                !Regex("^(?:[0-9a-fA-F]{2}){1,8}$").matches(sid) ||
                fp !in setOf("chrome", "firefox", "safari", "ios", "edge", "random", "randomized", "qq", "360") ||
                flow !in listOf("", "xtls-rprx-vision") ||
                (transport == "grpc" && (flow.isNotEmpty() || q["mode"].orEmpty() !in listOf("", "multi"))) ||
                q.getOrDefault("encryption", "none") != "none" ||
                !q.getOrDefault("spx", "/").startsWith('/') ||
                q.getOrDefault("spx", "/").length > 2048 ||
                q["serviceName"].orEmpty().length > 256
            ) {
                throw ApexApiException("invalid_link")
            }
            return ApexVless(
                uuid.lowercase(),
                uri.host,
                uri.port,
                transport,
                q["sni"]!!,
                key,
                sid.lowercase(),
                fp,
                q.getOrDefault("spx", "/"),
                flow,
                q["serviceName"].orEmpty(),
                q["mode"] == "multi",
            )
        } catch (_: Exception) {
            throw ApexApiException("invalid_link")
        }
    }

    fun grant(data: JsonObject): ApexGrant {
        val type = (data["type"] ?: data["protocol"])?.asString.orEmpty()
        val cityCode = data["city_code"]?.asString.orEmpty()
        if (type.equals("xray", true)) {
            runCatching {
                vless(
                    data["link"]?.asString.orEmpty(),
                )
            }.getOrNull()?.let { return ApexGrant("xray", "", "", emptyList(), cityCode, it) }
        }
        val username = data["username"]?.asString.orEmpty()
        val password = data["password"]?.asString.orEmpty()
        val endpoints =
            data
                .getAsJsonArray("servers")
                ?.map {
                    ApexEndpoint(it.asJsonObject["domain"].asString, it.asJsonObject["ip"].asString)
                }.orEmpty()
        if (username.isEmpty() ||
            password.isEmpty() ||
            !safeText(username, 4096) ||
            !safeText(password, 4096) ||
            endpoints.isEmpty() ||
            endpoints.any { !dnsName(it.domain) || !ipv4(it.ip) }
        ) {
            throw ApexApiException("invalid_response")
        }
        return ApexGrant("ikev2", username, password, endpoints, cityCode, null)
    }
}
