package com.windscribe.vpn.backend.xray

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import com.windscribe.vpn.api.apexguard.ApexVless
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.UUID

data class XrayTunnelConfig(
    val vless: ApexVless,
)

sealed interface XrayRuntimeState {
    data object Stopped : XrayRuntimeState

    data object Starting : XrayRuntimeState

    /** Local TUN/core ready. The backend still verifies Internet connectivity. */
    data object Started : XrayRuntimeState

    data class Failed(
        val message: String,
    ) : XrayRuntimeState
}

object XrayRuntime {
    private val mutableState = MutableStateFlow<XrayRuntimeState>(XrayRuntimeState.Stopped)
    val state: StateFlow<XrayRuntimeState> = mutableState.asStateFlow()

    @Volatile private var pending: XrayTunnelConfig? = null
    private var pendingToken: String? = null
    private var servicePresent = false

    @Synchronized fun start(
        context: Context,
        config: XrayTunnelConfig,
    ) {
        pending = config
        val token = UUID.randomUUID().toString().also { pendingToken = it }
        mutableState.value = XrayRuntimeState.Starting
        try {
            ContextCompat.startForegroundService(
                context,
                Intent(context, XrayVpnService::class.java)
                    .setAction(XrayVpnService.START)
                    .putExtra(XrayVpnService.REQUEST_TOKEN, token),
            )
        } catch (_: Exception) {
            pending = null
            pendingToken = null
            mutableState.value = XrayRuntimeState.Failed("VPN service could not start")
        }
    }

    @Synchronized fun stop(context: Context) {
        pending = null
        pendingToken = null
        if (!context.stopService(Intent(context, XrayVpnService::class.java)) &&
            !servicePresent
        ) {
            mutableState.value = XrayRuntimeState.Stopped
        }
    }

    @Synchronized internal fun takePending(token: String?): XrayTunnelConfig? {
        if (token == null || token != pendingToken) return null
        return pending.also {
            pending = null
            pendingToken = null
        }
    }

    @Synchronized internal fun serviceCreated() {
        servicePresent = true
    }

    @Synchronized internal fun serviceCleanedUp() {
        servicePresent = false
        mutableState.value = XrayRuntimeState.Stopped
    }

    internal fun publish(state: XrayRuntimeState) {
        mutableState.value = state
    }
}
