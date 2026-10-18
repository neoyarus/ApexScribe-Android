package com.windscribe.vpn.api.apexguard

import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class ApexContractsTest {
    private fun json(value: String) = JsonParser.parseString(value).asJsonObject

    private fun rejected(block: () -> Unit) {
        assertThrows(ApexApiException::class.java, block)
    }

    @Test fun gatewayRejectsCredentialDestinationsAndNonHttpsOrigins() {
        assertTrue(ApexContracts.gateway("https://gateway.apexguard.com"))
        listOf(
            "http://gateway.apexguard.com",
            "https://my.apexguard.com",
            "https://gateway.apexguard.com.evil.test",
            "https://user@gateway.apexguard.com",
            "https://gateway.apexguard.com:444",
            "https://gateway.apexguard.com/path",
            "https://gateway.apexguard.com?x=1",
        ).forEach {
            assertFalse(it, ApexContracts.gateway(it))
        }
    }

    @Test fun hostedLoginBindsExchangeAndReplacesMobileCallback() {
        val h = Base64.getEncoder().encodeToString("https://gateway.apexguard.com".toByteArray())
        val login = ApexContracts.hostedLogin(json("""{"auth":"https://my.apexguard.com/login?h=$h&device=desktop&redirect_url=evil"}"""))
        assertEquals("https://gateway.apexguard.com", login.origin)
        assertTrue(login.url.contains("device=mobile"))
        assertTrue(login.url.contains("redirect_url=apexguard%3A%2F%2Flogin"))
        assertFalse(login.url.contains("desktop"))
    }

    @Test fun hostedLoginRejectsForeignOrAmbiguousExchangeOrigin() {
        val h = Base64.getEncoder().encodeToString("https://evil.test".toByteArray())
        rejected { ApexContracts.hostedLogin(json("""{"auth":"https://my.apexguard.com/login?h=$h"}""")) }
        rejected { ApexContracts.hostedLogin(json("""{"auth":"https://my.apexguard.com/login?h=one&h=two"}""")) }
    }

    @Test fun callbackRequiresExpectedRouteAndSingleUnambiguousCode() {
        assertEquals("synthetic-code", ApexContracts.callbackCode("apexguard://login?status=done&exchange_token=synthetic-code"))
        listOf(
            "apexguard://other?status=done&exchange_token=a",
            "apexguard://login/path?status=done&exchange_token=a",
            "apexguard://login?status=done&exchange_token=a&exchange_token=b",
            "apexguard://login?status=done&action=logout&exchange_token=a",
            "apexguard://login?status=done&exchange_token=a%0D%0A",
            "apexguard://login?status=done&exchange_token=a#fragment",
        ).forEach {
            rejected { ApexContracts.callbackCode(it) }
        }
    }

    @Test fun tokenPairsMustBeCompleteAndNeverStringifySecrets() {
        rejected { ApexContracts.tokens(json("""{"access_token":"synthetic-access"}""")) }
        rejected { ApexContracts.tokens(json("""{"access_token":"bad\nvalue","refresh_token":"synthetic-refresh"}""")) }
        val pair = ApexContracts.tokens(json("""{"access_token":"synthetic-access","refresh_token":"synthetic-refresh"}"""))
        assertFalse(pair.toString().contains(pair.access))
        assertFalse(pair.toString().contains(pair.refresh))
    }

    @Test fun cityIdsRemainStableAcrossCatalogOrderAndCountries() {
        val first = ApexCity("Country", "AAA", "City", "ABC", 0.0, 0.0)
        val second = first.copy(countryCode = "AAB")
        assertNotEquals(first.id, second.id)
        assertEquals(first.id, first.copy(name = "Renamed").id)
    }

    @Test fun catalogRejectsDuplicateCitiesAndOutOfRangeCoordinates() {
        val row = """{"country":"Country","country_code":"AAA","city":"City","code":"ABC","coordinates":{"lat":0,"lon":0}}"""
        rejected { ApexContracts.cities(JsonParser.parseString("[$row,$row]")) }
        rejected { ApexContracts.cities(JsonParser.parseString("[${row.replace("\"lat\":0", "\"lat\":91")} ]")) }
    }

    private val vless =
        "vless://11111111-1111-4111-8111-111111111111@server.example:443" +
            "?security=reality&sni=www.example.com&pbk=${"A".repeat(43)}" +
            "&sid=abcd&type=tcp&fp=android&flow=xtls-rprx-vision"

    @Test fun validRealityLinkNormalizesTransportAndFingerprintWithoutLoggingCredentials() {
        val link = ApexContracts.vless(vless)
        assertEquals("raw", link.transport)
        assertEquals("chrome", link.fingerprint)
        assertFalse(link.toString().contains(link.uuid))
    }

    @Test fun unsafeRealityLinksAndInvalidGrpcCombinationsAreRejected() {
        listOf(
            vless + "&allowInsecure=1",
            vless.replace("security=reality", "security=none"),
            vless.replace("type=tcp", "type=grpc"),
            vless.replace("sid=abcd", "sid=not-hex"),
            vless.replace("server.example", "127.0.0.1"),
            vless + "&sni=other.example",
        ).forEach { rejected { ApexContracts.vless(it) } }
    }

    @Test fun invalidXrayLinkCanOnlyFallbackUsingTheSameGrantsValidIkev2Fields() {
        rejected { ApexContracts.grant(json("""{"type":"xray","link":"invalid"}""")) }
        val grant =
            ApexContracts.grant(
                json(
                    """{"type":"xray","link":"invalid","username":"synthetic-user","password":"synthetic-password","servers":[{"domain":"vpn.example","ip":"192.0.2.10"}]}""",
                ),
            )
        assertEquals("ikev2", grant.protocol)
        assertEquals("192.0.2.10", grant.endpoints.first().ip)
        assertFalse(grant.toString().contains(grant.password))
    }
}
