package com.windscribe.mobile

import android.content.Context
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.windscribe.mobile.ui.AppStartActivity
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URI

@RunWith(AndroidJUnit4::class)
class ApexDeviceSmokeTest {
    @Test
    fun bundledIkev2NativeBridgeLoads() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        // Class initialization loads androidbridge and its strongSwan dependencies.
        val application = Class.forName("org.strongswan.android.logic.StrongSwanApplication")
        application.getMethod("setContext", Context::class.java).invoke(null, context)
        assertEquals(context, application.getMethod("getContext").invoke(null))
    }

    @Test
    fun stockActivityStartsWithIsolatedPackage() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        assertEquals("com.apexscribe.android", context.packageName)
        val activity =
            instrumentation.startActivitySync(
                Intent(context, AppStartActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        instrumentation.waitForIdleSync()
        assertTrue(activity is AppStartActivity)
        assertTrue(!activity.isFinishing)
    }

    @Test
    fun providerMetadataOpensValidatedHostedLogin() =
        runBlocking {
            val instrumentation = InstrumentationRegistry.getInstrumentation()
            val context = instrumentation.targetContext
            val activity =
                instrumentation.startActivitySync(
                    Intent(context, AppStartActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                ) as AppStartActivity
            val service = activity.apexGuardService
            // Do not disrupt an account that has already signed in on the test tablet.
            if (service.authenticated.value) return@runBlocking
            try {
                val link = URI(withTimeout(120_000) { service.beginLogin() })
                assertEquals("https", link.scheme)
                assertEquals("my.apexguard.com", link.host)
                assertTrue(link.rawQuery.contains("apexguard%3A%2F%2Flogin"))
            } finally {
                service.cancelLogin()
            }
        }
}
