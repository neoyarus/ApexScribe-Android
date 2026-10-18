package com.windscribe.mobile.ui.auth

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.windscribe.vpn.api.apexguard.ApexGuardService
import com.windscribe.vpn.apppreference.PreferencesHelper
import com.windscribe.vpn.backend.VPNState.Status.Connected
import com.windscribe.vpn.repository.UserDataState
import com.windscribe.vpn.repository.UserRepository
import com.windscribe.vpn.state.VPNConnectionStateManager
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

sealed class SsoLoginState {
    object Idle : SsoLoginState()

    data class LoggingIn(
        val message: String,
    ) : SsoLoginState()

    object Success : SsoLoginState()

    data class Error(
        val error: String,
    ) : SsoLoginState()
}

abstract class AppStartViewModel : ViewModel() {
    abstract val loginState: StateFlow<SsoLoginState>

    abstract fun onSignIntentResult(data: Intent?)

    abstract val isConnected: StateFlow<Boolean>
    abstract val loggedIn: Boolean
    abstract val signInIntent: Intent?

    abstract fun clearLoginState()

    abstract fun onSignIntentLaunch()

    abstract fun beginHostedLogin(kind: String)
}

@HiltViewModel
class AppStartViewModelImpl
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
        private val preferencesHelper: PreferencesHelper,
        private val vpnConnectionStateManager: VPNConnectionStateManager,
        private val userRepository: UserRepository,
        private val service: ApexGuardService,
    ) : AppStartViewModel() {
        private val _isConnected = MutableStateFlow(false)
        override val isConnected: StateFlow<Boolean> = _isConnected.asStateFlow()
        override val loggedIn: Boolean = service.authenticated.value && preferencesHelper.sessionHash != null
        override val signInIntent: Intent? = null
        private val _loginState = MutableStateFlow<SsoLoginState>(SsoLoginState.Idle)
        private var prepareAfterLogin = !service.authenticated.value
        override val loginState: StateFlow<SsoLoginState> = _loginState.asStateFlow()

        init {
            viewModelScope.launch {
                vpnConnectionStateManager.state.collect { _isConnected.value = it.status == Connected }
            }
            viewModelScope.launch {
                service.authenticated.collect { authenticated ->
                    if (authenticated && prepareAfterLogin) {
                        prepareAfterLogin = false
                        preferencesHelper.sessionHash = ApexGuardService.SESSION_MARKER
                        prepareDashboard()
                    }
                }
            }
            viewModelScope.launch {
                service.loginFailed.collect {
                    if (it) {
                        _loginState.value =
                            SsoLoginState.Error(context.getString(com.windscribe.vpn.R.string.no_internet))
                    }
                }
            }
        }

        override fun beginHostedLogin(kind: String) {
            if (_loginState.value is SsoLoginState.LoggingIn) return
            viewModelScope.launch {
                _loginState.value = SsoLoginState.LoggingIn("Logging in")
                try {
                    if (service.authenticated.value) {
                        prepareDashboard()
                        return@launch
                    }
                    val url = withContext(Dispatchers.IO) { service.beginLogin(kind) }
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    _loginState.value = SsoLoginState.Idle
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    _loginState.value = SsoLoginState.Error(context.getString(com.windscribe.vpn.R.string.no_internet))
                }
            }
        }

        override fun onSignIntentLaunch() = beginHostedLogin("google")

        private suspend fun prepareDashboard() =
            withContext(Dispatchers.IO) {
                userRepository.prepareDashboard(null).collect {
                    _loginState.value =
                        when (it) {
                            is UserDataState.Success -> SsoLoginState.Success
                            is UserDataState.Loading -> SsoLoginState.LoggingIn(it.status)
                            is UserDataState.Error -> SsoLoginState.Error(context.getString(com.windscribe.vpn.R.string.no_internet))
                        }
                }
            }

        override fun onSignIntentResult(data: Intent?) = Unit

        override fun clearLoginState() {
            _loginState.value = SsoLoginState.Idle
        }
    }
