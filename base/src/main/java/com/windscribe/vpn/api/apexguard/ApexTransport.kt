package com.windscribe.vpn.api.apexguard

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.windscribe.vpn.commonutils.WindUtilities
import com.windscribe.vpn.wsnet.WSNetWrapper
import com.wsnet.lib.WSNetCancelableCallback
import com.wsnet.lib.WSNetHttpNetworkManager
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.net.Inet4Address
import java.net.URI
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

@Singleton
class ApexTransport
    @Inject
    constructor(
        private val wsnet: WSNetWrapper,
        private val store: ApexTokenStore,
        @ApplicationContext context: Context,
    ) {
        // Native peers are weakly referenced by wsnet: retain this one for the process lifetime.
        private var manager: WSNetHttpNetworkManager? = null
        private var socketCallback: WSNetCancelableCallback? = null
        private val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        private val sendMutex = Mutex()

        @Volatile private var activeNetwork: Network? = null
        private var knownSockets = emptySet<Int>()

        private fun network(physical: Boolean): Network =
            connectivity.allNetworks.firstOrNull { candidate ->
                val caps = connectivity.getNetworkCapabilities(candidate)
                caps != null &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) != physical
            } ?: throw ApexApiException(if (physical) "physical_network_unavailable" else "tunnel_unavailable")

        private suspend fun manager(): WSNetHttpNetworkManager {
            wsnet.awaitServerAPI()
            return synchronized(this) {
                manager ?: wsnet.getInstance()!!.httpNetworkManager().also { peer ->
                    socketCallback =
                        peer.setWhitelistSocketsCallback { sockets ->
                            // wsnet calls this synchronously before curl connects each new socket.
                            val added = sockets.toSet() - knownSockets
                            knownSockets = sockets.toSet()
                            added.forEach { fd ->
                                runCatching {
                                    ParcelFileDescriptor.fromFd(fd).use { parcel ->
                                        try {
                                            (activeNetwork ?: network(true)).bindSocket(parcel.fileDescriptor)
                                        } catch (
                                            failure: Exception,
                                        ) {
                                            runCatching { Os.shutdown(parcel.fileDescriptor, OsConstants.SHUT_RDWR) }
                                            throw failure
                                        }
                                    }
                                }
                            }
                        }
                    manager = peer
                }
            }
        }

        private val gateways =
            listOf(
                "z0yqxv9jrcmuhb",
                "p3vnqlz9kxdusz",
                "mjkt05wv3qward",
                "uf7lqmk20apar1",
                "xjwr79qhetmil6",
                "d0axv7pgzmmanz",
                "l5znx8wj9ilon1",
                "rqytfxmuo1ska",
                "rz15gvu8ssofe",
                "kf9u4zxy2pmadl",
                "fslgh4rcu1nys",
                "btlwqyfk62chy",
                "q9fx2ukn7dtaml",
                "yvuc92go4jset",
                "hg2mw8ctz5dalp",
                "rc898sdtxosa5",
                "zmwa0nct9lad",
            ).map {
                "https://$it.apexguard.com"
            }

        suspend fun request(
            method: String,
            path: String,
            body: JsonObject = JsonObject(),
            headers: Map<String, String> = emptyMap(),
            boundOrigin: String? = null,
            physical: Boolean = true,
        ): JsonElement {
            if (boundOrigin != null) return send(boundOrigin, method, path, body, headers, physical)
            val candidates = (listOfNotNull(store.gateway) + gateways).distinct()
            var selected: String? = null
            for (origin in candidates) {
                try {
                    val metadata = send(origin, "GET", "/v1/auth-links", JsonObject(), emptyMap(), physical)
                    store.gateway = origin
                    if (method == "GET" && path == "/v1/auth-links" && headers.isEmpty()) return metadata
                    selected = origin
                    break
                } catch (_: TimeoutCancellationException) {
                    // A per-probe deadline may advance to the next gateway. A cancelled
                    // caller (including its enclosing deadline) must still stop immediately.
                    currentCoroutineContext().ensureActive()
                } catch (cancelled: kotlinx.coroutines.CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                }
            }
            return send(selected ?: throw ApexApiException("gateway_unavailable"), method, path, body, headers, physical)
        }

        private suspend fun send(
            origin: String,
            method: String,
            path: String,
            body: JsonObject,
            headers: Map<String, String>,
            physical: Boolean,
        ): JsonElement =
            sendMutex.withLock {
                if (!ApexContracts.gateway(origin) ||
                    method !in listOf("GET", "POST") ||
                    !path.startsWith("/v") ||
                    path.any { it == '\r' || it == '\n' } ||
                    headers.any { (k, v) -> !ApexContracts.safeText(k, 256) || !ApexContracts.safeText(v, 65536) }
                ) {
                    throw ApexApiException("invalid_request")
                }
                val peer = manager()
                val route = network(physical)
                val address =
                    withContext(Dispatchers.IO) { route.getAllByName(URI(origin).host).firstOrNull { it is Inet4Address }?.hostAddress }
                        ?: throw ApexApiException("network_error")
                val timeout = if (method == "GET") 5000 else 15000
                val request =
                    if (method ==
                        "GET"
                    ) {
                        peer.createGetRequest(origin.trimEnd('/') + path, timeout, false)
                    } else {
                        peer.createPostRequest(origin.trimEnd('/') + path, timeout, body.toString(), false)
                    }
                request.setIgnoreSslErrors(false)
                request.setIsDebugLogCurlError(false)
                request.setIsEnableFreshConnect(true)
                request.setOverrideIp(address)
                activeNetwork = route
                request.addHttpHeader("Accept: application/json")
                request.addHttpHeader("User-Agent: ApexScribe/${WindUtilities.getVersionName()} (Android;)")
                if (method == "POST") request.addHttpHeader("Content-Type: application/json")
                headers.forEach { (name, value) -> request.addHttpHeader("$name: $value") }
                // executeRequest sends once. Gateway failover is restricted to the public GET probe above.
                try {
                    withTimeout((timeout + 2000).toLong()) {
                        suspendCancellableCoroutine { continuation ->
                            val callback =
                                peer.executeRequest(request, 0L) { _, _, error, response ->
                                    if (!continuation.isActive) return@executeRequest
                                    try {
                                        val status = error.httpResponseCode()
                                        if (status in 300..399) throw ApexApiException("redirect_refused", status)
                                        if (!error.isSuccess && status == 0) throw ApexApiException("network_error")
                                        if (response.length > 2 * 1024 * 1024) throw ApexApiException("invalid_response", status)
                                        if (status == 204 && response.isEmpty()) {
                                            continuation.resume(JsonObject())
                                            return@executeRequest
                                        }
                                        val envelope = JsonParser.parseString(response).asJsonObject
                                        if (status !in 200..299) {
                                            val code =
                                                listOf("code", "error", "message").firstNotNullOfOrNull {
                                                    envelope[it]
                                                        ?.takeIf { v ->
                                                            v.isJsonPrimitive
                                                        }?.asString
                                                }
                                            val allowed =
                                                setOf(
                                                    "server_not_available",
                                                    "connection_limit_reached",
                                                    "invalid_token",
                                                    "token_expired",
                                                    "access_token_expired",
                                                )
                                            throw ApexApiException(
                                                code?.takeIf { it in allowed } ?: if (status == 401) "invalid_token" else "provider_error",
                                                status,
                                            )
                                        }
                                        continuation.resume(envelope["data"] ?: throw ApexApiException("invalid_response", status))
                                    } catch (
                                        failure: ApexApiException,
                                    ) {
                                        continuation.resumeWithException(failure)
                                    } catch (
                                        _: Exception,
                                    ) {
                                        continuation.resumeWithException(ApexApiException("invalid_response"))
                                    }
                                }
                            continuation.invokeOnCancellation { callback.cancel() }
                        }
                    }
                } catch (_: TimeoutCancellationException) {
                    // An individual HTTP deadline is a transport failure. Preserve a
                    // caller's cancellation, but do not cancel its tunnel cleanup.
                    currentCoroutineContext().ensureActive()
                    throw ApexApiException("timeout")
                } finally {
                    activeNetwork = null
                }
            }
    }
