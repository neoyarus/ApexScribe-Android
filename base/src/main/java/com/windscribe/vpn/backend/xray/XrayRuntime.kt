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
    private var activeToken: String? = null
    private var serviceOwner: String? = null
    private var stopHandler: (() -> Unit)? = null

    @Synchronized fun start(
        context: Context,
        config: XrayTunnelConfig,
    ) {
        pending = config
        val token = UUID.randomUUID().toString().also { pendingToken = it }
        activeToken = token
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
            activeToken = null
            mutableState.value = XrayRuntimeState.Failed("VPN service could not start")
        }
    }

    fun stop(context: Context) {
        val handler =
            synchronized(this) {
                pending = null
                pendingToken = null
                activeToken = null
                stopHandler
            }
        if (handler != null) {
            // Android keeps an established VpnService bound until its TUN closes.
            // Explicit cleanup must therefore precede stopSelf/onDestroy.
            handler()
        } else {
            context.stopService(Intent(context, XrayVpnService::class.java))
            synchronized(this) {
                if (activeToken == null && serviceOwner == null) mutableState.value = XrayRuntimeState.Stopped
            }
        }
    }

    @Synchronized internal fun takePending(token: String?): XrayTunnelConfig? {
        if (token == null || token != pendingToken || token != activeToken) return null
        return pending.also {
            pending = null
            pendingToken = null
        }
    }

    internal fun serviceCreated(
        owner: String,
        stop: () -> Unit,
    ) {
        val alreadyStopped =
            synchronized(this) {
                serviceOwner = owner
                stopHandler = stop
                activeToken == null
            }
        if (alreadyStopped) stop()
    }

    @Synchronized internal fun serviceCleanedUp(
        owner: String,
        token: String?,
    ) {
        if (serviceOwner != owner) return
        serviceOwner = null
        stopHandler = null
        if (activeToken == null || activeToken == token) {
            activeToken = null
            mutableState.value = XrayRuntimeState.Stopped
        }
    }

    @Synchronized internal fun isCurrent(token: String?): Boolean = token != null && token == activeToken

    @Synchronized internal fun publish(
        state: XrayRuntimeState,
        token: String?,
    ) {
        if (isCurrent(token)) mutableState.value = state
    }
}
