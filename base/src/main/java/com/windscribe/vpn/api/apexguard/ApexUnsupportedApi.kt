package com.windscribe.vpn.api.apexguard

import com.windscribe.vpn.api.IApiCallManager
import com.windscribe.vpn.api.response.AddEmailResponse
import com.windscribe.vpn.api.response.ApiErrorResponse
import com.windscribe.vpn.api.response.AuthToken
import com.windscribe.vpn.api.response.BillingPlanResponse
import com.windscribe.vpn.api.response.CheckUpdateResponse
import com.windscribe.vpn.api.response.ClaimAccountResponse
import com.windscribe.vpn.api.response.ClaimVoucherCodeResponse
import com.windscribe.vpn.api.response.GeneratePasswordResponse
import com.windscribe.vpn.api.response.GenerateUsernameResponse
import com.windscribe.vpn.api.response.GenericResponseClass
import com.windscribe.vpn.api.response.GenericSuccess
import com.windscribe.vpn.api.response.GetMyIpResponse
import com.windscribe.vpn.api.response.LocationResponse
import com.windscribe.vpn.api.response.NewsFeedNotification
import com.windscribe.vpn.api.response.PortMapResponse
import com.windscribe.vpn.api.response.RobertFilterResponse
import com.windscribe.vpn.api.response.ServerCredentialsResponse
import com.windscribe.vpn.api.response.ServerResponse
import com.windscribe.vpn.api.response.SsoResponse
import com.windscribe.vpn.api.response.StaticIPResponse
import com.windscribe.vpn.api.response.TicketResponse
import com.windscribe.vpn.api.response.UnblockWgResponse
import com.windscribe.vpn.api.response.UserLoginResponse
import com.windscribe.vpn.api.response.UserRegistrationResponse
import com.windscribe.vpn.api.response.UserSessionResponse
import com.windscribe.vpn.api.response.VerifyExpressLoginResponse
import com.windscribe.vpn.api.response.WebSession
import com.windscribe.vpn.api.response.WgInitResponse
import com.windscribe.vpn.api.response.XPressLoginCodeResponse
import com.windscribe.vpn.api.response.XPressLoginVerifyResponse
import com.windscribe.vpn.constants.NetworkErrorCodes

/** Unsupported upstream services never receive a provider session or user input. */
abstract class ApexUnsupportedApi : IApiCallManager {
    protected fun <T> unsupported(): GenericResponseClass<T?, ApiErrorResponse?> =
        GenericResponseClass(
            null,
            ApiErrorResponse().apply {
                errorCode = NetworkErrorCodes.ERROR_UNABLE_TO_REACH_API
                errorMessage = "Network error, unable to connect to server."
            },
        )

    override suspend fun addUserEmailAddress(email: String): GenericResponseClass<AddEmailResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun getApiIp(): GenericResponseClass<GetMyIpResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun getIp(): GenericResponseClass<String?, ApiErrorResponse?> = unsupported()

    override suspend fun claimAccount(
        username: String,
        password: String,
        email: String,
        voucherCode: String?,
    ): GenericResponseClass<ClaimAccountResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun getBillingPlans(promo: String?): GenericResponseClass<BillingPlanResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun getNotifications(pcpID: String?): GenericResponseClass<NewsFeedNotification?, ApiErrorResponse?> = unsupported()

    override suspend fun getPortMap(): GenericResponseClass<PortMapResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun getServerConfig(): GenericResponseClass<String?, ApiErrorResponse?> = unsupported()

    override suspend fun getServerCredentials(
        extraParams: Map<String, String>?,
    ): GenericResponseClass<ServerCredentialsResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun getServerCredentialsForIKev2(
        extraParams: Map<String, String>?,
    ): GenericResponseClass<ServerCredentialsResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun getServerList(
        isPro: Boolean,
        locHash: String,
        alcList: Array<String>,
        overriddenCountryCode: String?,
    ): GenericResponseClass<String?, ApiErrorResponse?> = unsupported()

    override suspend fun getSessionGeneric(
        firebaseToken: String?,
        backup: Int,
    ): GenericResponseClass<UserSessionResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun getStaticIpList(deviceID: String?): GenericResponseClass<StaticIPResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun logUserIn(
        username: String,
        password: String,
        twoFa: String?,
        secureToken: String?,
        captchaSolution: String?,
        captchaTrailX: FloatArray,
        captchaTrailY: FloatArray,
        installer: String?,
    ): GenericResponseClass<UserLoginResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun getWebSession(): GenericResponseClass<WebSession?, ApiErrorResponse?> = unsupported()

    override suspend fun checkUpdate(
        appVersion: String,
        appBuild: String,
        osVersion: String,
    ): GenericResponseClass<CheckUpdateResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun recordAppInstall(): GenericResponseClass<String?, ApiErrorResponse?> = unsupported()

    override suspend fun resendUserEmailAddress(
        extraParams: Map<String, String>?,
    ): GenericResponseClass<AddEmailResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun sendTicket(
        supportEmail: String,
        supportName: String,
        supportSubject: String,
        supportMessage: String,
        supportCategory: String,
        type: String,
        channel: String,
    ): GenericResponseClass<TicketResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun signUserIn(
        username: String,
        password: String,
        referringUsername: String?,
        email: String?,
        voucherCode: String?,
        secureToken: String?,
        captchaSolution: String?,
        captchaTrailX: FloatArray,
        captchaTrailY: FloatArray,
        integrityToken: String?,
        installer: String?,
    ): GenericResponseClass<UserRegistrationResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun claimVoucherCode(voucherCode: String): GenericResponseClass<ClaimVoucherCodeResponse?, ApiErrorResponse?> =
        unsupported()

    override suspend fun signUpUsingToken(
        token: String,
        integrityToken: String?,
        installer: String?,
    ): GenericResponseClass<UserRegistrationResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun verifyPurchaseReceipt(
        purchaseToken: String,
        gpPackageName: String,
        gpProductId: String,
        type: String,
        amazonUserId: String,
    ): GenericResponseClass<GenericSuccess?, ApiErrorResponse?> = unsupported()

    override suspend fun verifyExpressLoginCode(loginCode: String): GenericResponseClass<VerifyExpressLoginResponse?, ApiErrorResponse?> =
        unsupported()

    override suspend fun generateXPressLoginCode(): GenericResponseClass<XPressLoginCodeResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun verifyXPressLoginCode(
        loginCode: String,
        signature: String,
    ): GenericResponseClass<XPressLoginVerifyResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun postDebugLog(
        username: String,
        log: String,
    ): GenericResponseClass<GenericSuccess?, ApiErrorResponse?> = unsupported()

    override suspend fun postPromoPaymentConfirmation(pcpID: String): GenericResponseClass<GenericSuccess?, ApiErrorResponse?> =
        unsupported()

    override suspend fun getRobertFilters(): GenericResponseClass<RobertFilterResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun updateRobertSettings(
        id: String,
        status: Int,
    ): GenericResponseClass<GenericSuccess?, ApiErrorResponse?> = unsupported()

    override suspend fun syncRobert(): GenericResponseClass<GenericSuccess?, ApiErrorResponse?> = unsupported()

    override suspend fun deleteSession(): GenericResponseClass<GenericSuccess?, ApiErrorResponse?> = unsupported()

    override suspend fun wgInit(
        clientPublicKey: String,
        deleteOldestKey: Boolean,
    ): GenericResponseClass<WgInitResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun sendDecoyTraffic(
        url: String,
        data: String,
        sizeToReceive: String?,
    ): GenericResponseClass<String?, ApiErrorResponse?> = unsupported()

    override suspend fun sso(
        provider: String,
        token: String,
        integrityToken: String?,
        installer: String?,
    ): GenericResponseClass<SsoResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun authTokenSignup(
        username: String,
        useAsciiCaptcha: Boolean,
    ): GenericResponseClass<AuthToken?, ApiErrorResponse?> = unsupported()

    override suspend fun authTokenLogin(
        username: String,
        useAsciiCaptcha: Boolean,
    ): GenericResponseClass<AuthToken?, ApiErrorResponse?> = unsupported()

    override suspend fun rotateIp(): GenericResponseClass<String?, ApiErrorResponse?> = unsupported()

    override suspend fun pinIp(ip: String?): GenericResponseClass<String?, ApiErrorResponse?> = unsupported()

    override suspend fun passwordRecovery(email: String?): GenericResponseClass<GenericSuccess?, ApiErrorResponse?> = unsupported()

    override suspend fun unblockWgParams(): GenericResponseClass<UnblockWgResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun getLocations(): GenericResponseClass<LocationResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun getServers(backup: Int): GenericResponseClass<ServerResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun generateUsername(): GenericResponseClass<GenerateUsernameResponse?, ApiErrorResponse?> = unsupported()

    override suspend fun generatePassword(): GenericResponseClass<GeneratePasswordResponse?, ApiErrorResponse?> = unsupported()
}
