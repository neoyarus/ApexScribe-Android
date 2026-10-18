package com.windscribe.mobile.ui.nav

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ApexNavigationPolicyTest {
    @Test fun apexBlocksStockAccountBillingSupportAndLoginDestinations() {
        listOf(
            "login",
            "signup",
            "two_factor",
            "emergency_connect",
            "no_email_attention",
            "newsfeed",
            "anti_censorship",
            "robert",
            "ticket",
            "share_link",
            "account_status",
            "account",
            "add_email",
            "confirm_email",
            "upgrade",
            "upgrade_success",
            "edit_custom_config",
            "debug_log_sent",
            "extra_data_use_warning",
        ).forEach { route ->
            assertFalse(route, ApexNavigationPolicy.isAllowed(route, true))
            assertTrue(route, ApexNavigationPolicy.isAllowed(route, false))
        }
    }

    @Test fun deepLinkArgumentsCannotMakeStockDestinationsAvailable() {
        listOf("upgrade?promo_code=example", "edit_custom_config/42", "ticket?source=push").forEach { route ->
            assertFalse(route, ApexNavigationPolicy.isAllowed(route, true))
            assertTrue(route, ApexNavigationPolicy.isAllowed(route, false))
        }
    }

    @Test fun apexKeepsProviderLoginLocalSettingsDiagnosticsAndGenericUpdatesAvailable() {
        listOf(
            Screen.Start,
            Screen.Home,
            Screen.Connection,
            Screen.SplitTunnel,
            Screen.ExcludedIpDomains,
            Screen.NetworkOptions,
            Screen.NetworkDetails,
            Screen.HelpMe,
            Screen.Advance,
            Screen.Debug,
            Screen.AllProtocolFailed,
            Screen.AllProtocolFailedDialog,
            Screen.ManualModeFailed,
            Screen.UpdateAvailable,
        ).forEach { screen ->
            assertTrue(screen.route, ApexNavigationPolicy.isAllowed(screen.route, true))
        }
    }
}
