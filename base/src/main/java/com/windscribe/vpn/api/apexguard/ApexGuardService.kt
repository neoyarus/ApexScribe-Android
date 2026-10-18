package com.windscribe.vpn.api.apexguard

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.atomic.AtomicLong
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ApexGuardService
    @Inject
    constructor(
        private val transport: ApexTransport,
        private val store: ApexTokenStore,
    ) {
        companion object {
            const val SESSION_MARKER = "apexguard:keystore:v1"
        }

        @Volatile private var tokens: ApexTokens? = runCatching { store.load() }.getOrNull()
        private val epoch = AtomicLong()
        private val authLock = Any()
        private val refreshMutex = Mutex()
        private val sessionMutex = Mutex()
        private val loginMutex = Mutex()
        private var pendingLogin: Pair<Long, ApexHostedLogin>? = null
        private val _authenticated = MutableStateFlow(tokens != null)
        val authenticated: StateFlow<Boolean> = _authenticated.asStateFlow()
        private val _loginFailed = MutableStateFlow(false)
        val loginFailed: StateFlow<Boolean> = _loginFailed.asStateFlow()

        @Volatile private var catalog: List<ApexCity> = emptyList()
        private var remoteCity: ApexCity? = null

        suspend fun beginLogin(kind: String = "auth"): String {
            val ticket = epoch.incrementAndGet()
            loginMutex.withLock {
                pendingLogin = null
                _loginFailed.value = false
            }
            val data = transport.request("GET", "/v1/auth-links").asJsonObject
            val selected = if (kind in listOf("register", "google")) data[kind] else data["auth"]
            val link =
                runCatching { ApexContracts.hostedLogin(JsonObject().apply { add("auth", selected) }) }.getOrElse {
                    if (kind == "register") throw it
                    ApexContracts.hostedLogin(data)
                }
            loginMutex.withLock {
                if (epoch.get() != ticket) throw ApexApiException("cancelled")
                pendingLogin = ticket to link
            }
            return link.url
        }

        suspend fun completeLogin(callback: String): Boolean =
            loginMutex.withLock {
                val pending = pendingLogin ?: return@withLock false
                pendingLogin = null
                try {
                    val code = ApexContracts.callbackCode(callback)
                    val result =
                        transport.request(
                            "POST",
                            "/v1/token",
                            JsonObject().apply { addProperty("auth_code", code) },
                            mapOf(
                                "Device-ID" to store.deviceId(),
                            ),
                            pending.second.origin,
                        )
                    val replacement = ApexContracts.tokens(result.asJsonObject)
                    synchronized(authLock) {
                        if (epoch.get() != pending.first) return@withLock false
                        store.save(replacement)
                        tokens = replacement
                        _authenticated.value = true
                    }
                    true
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    if (epoch.get() == pending.first) _loginFailed.value = true
                    false
                }
            }

        fun cancelLogin() {
            epoch.incrementAndGet()
        }

        private fun headers(pair: ApexTokens) = mapOf("Authorization" to "Bearer ${pair.access}", "Device-ID" to store.deviceId())

        suspend fun request(
            method: String,
            path: String,
            body: JsonObject = JsonObject(),
            physical: Boolean = true,
        ): JsonElement {
            val ticket = epoch.get()
            val snapshot = tokens ?: throw ApexApiException("signed_out", 401)
            try {
                val response = transport.request(method, path, body, headers(snapshot), physical = physical)
                if (ticket != epoch.get()) throw ApexApiException("signed_out", 401)
                return response
            } catch (error: ApexApiException) {
                if (error.status != 401 || ticket != epoch.get()) throw error
            }
            refreshMutex.withLock {
                if (ticket != epoch.get() || tokens == null) throw ApexApiException("signed_out", 401)
                if (tokens === snapshot) {
                    try {
                        val response =
                            transport.request(
                                "POST",
                                "/v1/refresh",
                                JsonObject().apply { addProperty("refresh_token", snapshot.refresh) },
                                mapOf(
                                    "Device-ID" to store.deviceId(),
                                ),
                            )
                        val replacement = ApexContracts.tokens(response.asJsonObject)
                        synchronized(authLock) {
                            if (ticket != epoch.get()) throw ApexApiException("signed_out", 401)
                            store.save(replacement)
                            tokens = replacement
                        }
                    } catch (error: ApexApiException) {
                        if (error.status == 401 && ticket == epoch.get()) {
                            synchronized(authLock) {
                                if (ticket == epoch.get()) {
                                    epoch.incrementAndGet()
                                    tokens = null
                                    _authenticated.value = false
                                    store.clear()
                                }
                            }
                        }
                        throw error
                    }
                }
            }
            val active = tokens ?: throw ApexApiException("signed_out", 401)
            val response = transport.request(method, path, body, headers(active), physical = physical)
            if (ticket != epoch.get()) throw ApexApiException("signed_out", 401)
            return response
        }

        suspend fun cities(): List<ApexCity> {
            val rows = ApexContracts.cities(request("GET", "/v1/cities"))
            if (rows.isEmpty()) throw ApexApiException("server_not_available")
            catalog = rows
            return rows
        }

        suspend fun myIp(physical: Boolean = true): String {
            val ip = request("GET", "/v1/my-ip", physical = physical).asJsonObject["ip"]?.asString.orEmpty()
            if (!ApexContracts.ipv4(ip)) throw ApexApiException("invalid_response")
            return ip
        }

        suspend fun connect(
            datacenterId: Int,
            protocol: String?,
            reconnect: Boolean = false,
        ): ApexGrant =
            sessionMutex.withLock {
                val city =
                    (catalog.ifEmpty { cities() }).firstOrNull { it.id == datacenterId } ?: throw ApexApiException("server_not_available")
                val previous = remoteCity
                val path =
                    when {
                        previous != null && previous.id != city.id -> "/v2/switch"
                        reconnect || previous != null -> "/v2/reconnect"
                        else -> "/v2/connect"
                    }
                val body =
                    JsonObject().apply {
                        addProperty("city_code", city.code)
                        addProperty("country_code", city.countryCode)
                        addProperty("is_fastest", false)
                        addProperty("ip", myIp())
                        if (protocol?.lowercase() in listOf("ikev2", "xray")) addProperty("type", protocol!!.lowercase())
                        if (path == "/v2/switch" &&
                            previous != null
                        ) {
                            addProperty("from_city_code", previous.code)
                            addProperty("from_country_code", previous.countryCode)
                        }
                    }
                remoteCity = city // A sent POST may have succeeded even when its response is lost or invalid.
                val grant = ApexContracts.grant(request("POST", path, body).asJsonObject)
                remoteCity = catalog.firstOrNull { it.code == grant.cityCode } ?: city
                grant
            }

        suspend fun disconnect() =
            sessionMutex.withLock {
                if (tokens != null && remoteCity != null) request("POST", "/v1/disconnect")
                remoteCity = null
                Unit
            }

        suspend fun logout() {
            val old =
                synchronized(authLock) {
                    val previous = tokens
                    epoch.incrementAndGet()
                    tokens = null
                    _authenticated.value = false
                    store.clear()
                    previous
                }
            catalog = emptyList()
            // Local sign out is durable even when the network is unavailable.
            sessionMutex.withLock {
                remoteCity = null
                if (old != null) {
                    try {
                        transport.request("POST", "/v1/disconnect", headers = headers(old))
                    } catch (
                        cancelled: CancellationException,
                    ) {
                        throw cancelled
                    } catch (_: Exception) {
                    }
                    try {
                        transport.request("POST", "/v1/logout", headers = headers(old))
                    } catch (
                        cancelled: CancellationException,
                    ) {
                        throw cancelled
                    } catch (_: Exception) {
                    }
                }
            }
        }
    }
