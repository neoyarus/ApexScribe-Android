package com.windscribe.mobile.ui.nav

internal object ApexNavigationPolicy {
    private val windscribeRoutes =
        setOf(
            Screen.Login.route,
            Screen.Signup.route,
            Screen.TwoFactor.route,
            Screen.EmergencyConnect.route,
            Screen.NoEmailAttention.route,
            Screen.Newsfeed.route,
            Screen.AntiCensorship.route,
            Screen.Robert.route,
            Screen.Ticket.route,
            Screen.ShareLink.route,
            Screen.AccountStatus.route,
            Screen.Account.route,
            Screen.AddEmail.route,
            Screen.ConfirmEmail.route,
            Screen.Upgrade.route,
            Screen.UpgradeSuccess.route,
            Screen.EditCustomConfig.route,
            Screen.DebugLogSent.route,
            Screen.ExtraDataUseWarning.route,
        )

    fun isAllowed(
        route: String,
        apexGuardEnabled: Boolean,
    ): Boolean = !apexGuardEnabled || route.substringBefore('?').substringBefore('/') !in windscribeRoutes
}
