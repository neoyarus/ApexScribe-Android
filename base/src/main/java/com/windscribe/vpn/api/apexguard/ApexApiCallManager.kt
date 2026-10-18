package com.windscribe.vpn.api.apexguard

import com.google.gson.Gson
import com.google.gson.JsonObject
import com.windscribe.vpn.api.response.ApiErrorResponse
import com.windscribe.vpn.api.response.DatacenterData
import com.windscribe.vpn.api.response.GenericResponseClass
import com.windscribe.vpn.api.response.GenericSuccess
import com.windscribe.vpn.api.response.GetMyIpResponse
import com.windscribe.vpn.api.response.LocationData
import com.windscribe.vpn.api.response.LocationResponse
import com.windscribe.vpn.api.response.NewsFeedNotification
import com.windscribe.vpn.api.response.PortMapResponse
import com.windscribe.vpn.api.response.ServerData
import com.windscribe.vpn.api.response.ServerResponse
import com.windscribe.vpn.api.response.UnblockWgResponse
import com.windscribe.vpn.api.response.UserSessionResponse
import com.windscribe.vpn.apppreference.PreferencesHelper
import com.windscribe.vpn.constants.NetworkErrorCodes
import kotlinx.coroutines.CancellationException
import java.util.Locale
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ApexApiCallManager
    @Inject
    constructor(
        private val service: ApexGuardService,
        private val preferences: PreferencesHelper,
    ) : ApexUnsupportedApi() {
        private val gson = Gson()
        private var inventory: List<ApexCity> = emptyList()
        private val countryCodes by lazy {
            Locale.getISOCountries().associateBy {
                runCatching {
                    Locale(
                        "",
                        it,
                    ).isO3Country
                }.getOrDefault("")
            }
        }

        private suspend fun <T> response(block: suspend () -> T): GenericResponseClass<T?, ApiErrorResponse?> =
            try {
                GenericResponseClass(block(), null)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                val unauthorized = error is ApexApiException && error.status == 401
                if (unauthorized) preferences.sessionHash = null
                GenericResponseClass(
                    null,
                    ApiErrorResponse().apply {
                        errorCode =
                            if (unauthorized) {
                                NetworkErrorCodes.ERROR_RESPONSE_SESSION_INVALID
                            } else {
                                NetworkErrorCodes.ERROR_UNABLE_TO_REACH_API
                            }
                        // Use existing upstream copy; provider responses never become displayed text.
                        errorMessage = "Network error, unable to connect to server."
                    },
                )
            }

        override suspend fun getSessionGeneric(
            firebaseToken: String?,
            backup: Int,
        ): GenericResponseClass<UserSessionResponse?, ApiErrorResponse?> =
            response {
                inventory = service.cities()
                UserSessionResponse().apply {
                    providerManaged = true
                    userName = ""
                    userAccountStatus = 1
                    isPremium = 0
                    alcList = emptyList()
                    locationRevision = "1"
                }
            }

        override suspend fun getLocations(): GenericResponseClass<LocationResponse?, ApiErrorResponse?> =
            response {
                inventory = service.cities()
                LocationResponse(
                    inventory.groupBy { it.countryCode }.values.mapIndexed { index, cities ->
                        val first = cities.first()
                        LocationData(
                            first.countryId,
                            first.country,
                            countryCodes[first.countryCode].orEmpty(),
                            first.country,
                            0,
                            index,
                            "",
                            cities.map { city ->
                                DatacenterData(
                                    city.id,
                                    city.name,
                                    "",
                                    city.code,
                                    1,
                                    "${city.latitude},${city.longitude}",
                                    "",
                                    1,
                                    "",
                                    "",
                                    "",
                                    0,
                                    0,
                                )
                            },
                        )
                    },
                )
            }

        override suspend fun getServers(backup: Int): GenericResponseClass<ServerResponse?, ApiErrorResponse?> =
            response {
                if (inventory.isEmpty()) inventory = service.cities()
                // Cities have no permanent endpoint. Connection-specific grants supply native server addresses.
                ServerResponse(inventory.map { ServerData(it.id, "", "", "", "", it.id, 1, 0) }, 1)
            }

        override suspend fun getApiIp(): GenericResponseClass<GetMyIpResponse?, ApiErrorResponse?> =
            response {
                gson.fromJson(JsonObject().apply { addProperty("user_ip", service.myIp()) }, GetMyIpResponse::class.java)
            }

        override suspend fun getIp(): GenericResponseClass<String?, ApiErrorResponse?> = response { service.myIp(physical = false) }

        override suspend fun getPortMap(): GenericResponseClass<PortMapResponse?, ApiErrorResponse?> =
            response {
                gson.fromJson(
                    """{"portmap":[{"heading":"IKEv2","protocol":"ikev2","use":"hostname","ports":["500"]},{"heading":"Xray","protocol":"xray","use":"ip","ports":["443"]}],"suggested":{"protocol":"ikev2","port":500}}""",
                    PortMapResponse::class.java,
                )
            }

        override suspend fun deleteSession(): GenericResponseClass<GenericSuccess?, ApiErrorResponse?> =
            response {
                preferences.sessionHash = null
                service.logout()
                gson.fromJson("""{"success":1}""", GenericSuccess::class.java)
            }

        override suspend fun unblockWgParams(): GenericResponseClass<UnblockWgResponse?, ApiErrorResponse?> =
            response {
                UnblockWgResponse(emptyList())
            }

        override suspend fun getNotifications(pcpID: String?): GenericResponseClass<NewsFeedNotification?, ApiErrorResponse?> =
            response {
                NewsFeedNotification(emptyList())
            }
    }
