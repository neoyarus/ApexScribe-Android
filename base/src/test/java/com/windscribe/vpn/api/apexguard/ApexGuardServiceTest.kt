package com.windscribe.vpn.api.apexguard

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class ApexGuardServiceTest {
    private val transport = mockk<ApexTransport>()
    private val store = mockk<ApexTokenStore>(relaxed = true)
    private val original = ApexTokens("synthetic-old-access", "synthetic-old-refresh")

    private fun json(value: String) = JsonParser.parseString(value)

    private fun service(signedIn: Boolean = true): ApexGuardService {
        every { store.load() } returns if (signedIn) original else null
        every { store.deviceId() } returns "11111111-1111-4111-8111-111111111111"
        return ApexGuardService(transport, store)
    }

    @Test fun concurrentUnauthorizedRequestsShareOneRefreshAndUseRotatedPair() =
        runTest {
            val service = service()
            coEvery { transport.request(any(), any(), any(), any(), any(), any()) } coAnswers {
                if (secondArg<String>() == "/v1/refresh") {
                    delay(25)
                    json("""{"access_token":"synthetic-new-access","refresh_token":"synthetic-new-refresh"}""")
                } else {
                    if (arg<Map<String, String>>(3)["Authorization"] ==
                        "Bearer synthetic-old-access"
                    ) {
                        throw ApexApiException("invalid_token", 401)
                    }
                    JsonObject()
                }
            }
            List(8) { async { service.request("GET", "/v1/test") } }.awaitAll()
            coVerify(exactly = 1) { transport.request("POST", "/v1/refresh", any(), any(), any(), any()) }
            verify(exactly = 1) { store.save(match { it.access == "synthetic-new-access" && it.refresh == "synthetic-new-refresh" }) }
        }

    @Test fun logoutDuringRefreshCannotResurrectStoredOrActiveCredentials() =
        runTest {
            val service = service()
            val refreshing = CompletableDeferred<Unit>()
            val finishRefresh = CompletableDeferred<Unit>()
            coEvery { transport.request(any(), any(), any(), any(), any(), any()) } coAnswers {
                when (secondArg<String>()) {
                    "/v1/test" -> throw ApexApiException("invalid_token", 401)
                    "/v1/refresh" -> {
                        refreshing.complete(Unit)
                        finishRefresh.await()
                        json("""{"access_token":"synthetic-new-access","refresh_token":"synthetic-new-refresh"}""")
                    }
                    else -> JsonObject()
                }
            }
            val request = async { runCatching { service.request("GET", "/v1/test") } }
            refreshing.await()
            service.logout()
            finishRefresh.complete(Unit)
            assertTrue(request.await().isFailure)
            assertFalse(service.authenticated.value)
            verify(exactly = 0) { store.save(any()) }
            verify(exactly = 1) { store.clear() }
        }

    @Test fun exchangeRemainsBoundToHostedGatewayAndCannotCompleteAfterLogout() =
        runTest {
            val service = service(signedIn = false)
            val exchangeStarted = CompletableDeferred<Unit>()
            val finishExchange = CompletableDeferred<Unit>()
            val h = Base64.getEncoder().encodeToString("https://login-gateway.apexguard.com".toByteArray())
            coEvery { transport.request(any(), any(), any(), any(), any(), any()) } coAnswers {
                if (secondArg<String>() == "/v1/auth-links") {
                    json("""{"auth":"https://my.apexguard.com/login?h=$h"}""")
                } else {
                    exchangeStarted.complete(Unit)
                    finishExchange.await()
                    json("""{"access_token":"synthetic-access","refresh_token":"synthetic-refresh"}""")
                }
            }
            service.beginLogin()
            val completion = async { service.completeLogin("apexguard://login?status=done&exchange_token=synthetic-code") }
            exchangeStarted.await()
            service.logout()
            finishExchange.complete(Unit)
            assertFalse(completion.await())
            assertFalse(service.authenticated.value)
            verify(exactly = 0) { store.save(any()) }
            coVerify { transport.request("POST", "/v1/token", any(), any(), "https://login-gateway.apexguard.com", true) }
        }

    @Test fun disconnectWaitsForSentGrantAndRemainsIdempotent() =
        runTest {
            val service = service()
            val grantStarted = CompletableDeferred<Unit>()
            val finishGrant = CompletableDeferred<Unit>()
            val calls = mutableListOf<String>()
            coEvery { transport.request(any(), any(), any(), any(), any(), any()) } coAnswers {
                val path = secondArg<String>()
                calls += path
                when (path) {
                    "/v1/cities" ->
                        json(
                            """[{"country":"Country","country_code":"AAA","city":"City","code":"ABC","coordinates":{"lat":0,"lon":0}}]""",
                        )
                    "/v1/my-ip" -> json("""{"ip":"192.0.2.1"}""")
                    "/v2/connect" -> {
                        grantStarted.complete(Unit)
                        finishGrant.await()
                        json(
                            """{"username":"synthetic-user","password":"synthetic-password","servers":[{"domain":"vpn.example","ip":"192.0.2.2"}]}""",
                        )
                    }
                    else -> JsonObject()
                }
            }
            val city = ApexCity("Country", "AAA", "City", "ABC", 0.0, 0.0)
            val connection = async { service.connect(city.id, "ikev2") }
            grantStarted.await()
            val disconnection = async { service.disconnect() }
            delay(1)
            assertFalse(calls.contains("/v1/disconnect"))
            finishGrant.complete(Unit)
            connection.await()
            disconnection.await()
            service.disconnect()
            assertEquals(1, calls.count { it == "/v1/disconnect" })
            assertTrue(calls.indexOf("/v2/connect") < calls.indexOf("/v1/disconnect"))
        }
}
