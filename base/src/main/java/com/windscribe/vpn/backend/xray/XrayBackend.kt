package com.windscribe.vpn.backend.xray

import com.windscribe.vpn.Windscribe.Companion.appContext
import com.windscribe.vpn.api.IApiCallManager
import com.windscribe.vpn.api.apexguard.ApexGuardService
import com.windscribe.vpn.apppreference.PreferencesHelper
import com.windscribe.vpn.autoconnection.ProtocolInformation
import com.windscribe.vpn.backend.Util
import com.windscribe.vpn.backend.VPNState
import com.windscribe.vpn.backend.VpnBackend
import com.windscribe.vpn.backend.utils.ApexGuardGrantStore
import com.windscribe.vpn.commonutils.ResourceHelper
import com.windscribe.vpn.localdatabase.LocalDbInterface
import com.windscribe.vpn.repository.AdvanceParameterRepository
import com.windscribe.vpn.state.NetworkInfoManager
import com.windscribe.vpn.state.VPNConnectionStateManager
import com.windscribe.vpn.wsnet.WSNetWrapper
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class XrayBackend
    @Inject
    constructor(
        private val scope: CoroutineScope,
        stateManager: VPNConnectionStateManager,
        preferences: PreferencesHelper,
        networkInfoManager: NetworkInfoManager,
        advanceParameters: AdvanceParameterRepository,
        api: IApiCallManager,
        database: LocalDbInterface,
        wsNetWrapper: WSNetWrapper,
        resources: ResourceHelper,
        private val apexGuardService: ApexGuardService,
        private val apexGrantStore: ApexGuardGrantStore,
    ) : VpnBackend(scope, stateManager, preferences, networkInfoManager, advanceParameters, api, database, wsNetWrapper, resources) {
        override var active = false
        private var stateJob: Job? = null
        private val disconnectMutex = Mutex()

        override fun activate() {
            stateJob?.cancel()
            active = true
            startNetworkInfoObserver()
        }

        override fun connect(
            protocolInformation: ProtocolInformation,
            connectionId: UUID,
        ) {
            this.protocolInformation = protocolInformation
            this.connectionId = connectionId
            error = null
            val config = Util.getProfile<XrayTunnelConfig>()
            if (config == null) {
                scope.launch { disconnect(VPNState.Error(VPNState.ErrorType.GenericError)) }
                return
            }
            updateState(VPNState(VPNState.Status.Connecting))
            startConnectionJob()
            // start synchronously publishes Starting before observation, so a previous Stopped
            // value cannot terminate a new attempt. Started only means native readiness.
            try {
                XrayRuntime.start(appContext, config)
            } catch (_: Exception) {
                scope.launch { disconnect(VPNState.Error(VPNState.ErrorType.GenericError, showError = true)) }
                return
            }
            stateJob =
                scope.launch {
                    XrayRuntime.state.collectLatest { state ->
                        if (!active) return@collectLatest
                        when (state) {
                            XrayRuntimeState.Starting -> updateState(VPNState(VPNState.Status.Connecting))
                            XrayRuntimeState.Started -> testConnectivity()
                            XrayRuntimeState.Stopped -> {
                                scope.launch { disconnect(VPNState.Error(VPNState.ErrorType.BrokenTunnel)) }
                            }
                            is XrayRuntimeState.Failed -> {
                                scope.launch { disconnect(VPNState.Error(VPNState.ErrorType.GenericError, showError = true)) }
                            }
                        }
                    }
                }
        }

        override fun deactivate() {
            active = false
            stateJob?.cancel()
            stateJob = null
            stopNetworkInfoObserver()
        }

        override suspend fun disconnect(error: VPNState.Error?) =
            disconnectMutex.withLock {
                this.error = error
                connectionJob?.cancel()
                stateJob?.cancel()
                stateJob = null
                stopNetworkInfoObserver()
                XrayRuntime.stop(appContext)
                withTimeout(10_000) { XrayRuntime.state.first { it == XrayRuntimeState.Stopped } }
                Util.clearProfile()
                if (error?.error != VPNState.ErrorType.UserReconnect) {
                    apexGrantStore.clear()
                    try {
                        apexGuardService.disconnect()
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (_: Exception) {
                        vpnLogger.warn("Remote VPN session cleanup failed")
                    }
                }
                deactivate()
                updateState(VPNState(VPNState.Status.Disconnected, error = error))
            }
    }
