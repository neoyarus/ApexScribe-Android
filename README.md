# ApexScribe Android

ApexGuard client built from the official Windscribe Android application. The phone and tablet client retains upstream components, styling, assets, and localized copy, with Windscribe-only service controls hidden. Existing login, location, connection, protocol, and split-tunneling controls use the ApexGuard provider integration. The installed package is `com.apexscribe.android`, so it can coexist with Windscribe.

Android 10 or newer is required. IKEv2 uses bundled strongSwan; Xray uses VLESS/REALITY over raw TCP or gRPC with the pinned native dependencies described in [xray/README.md](xray/README.md). This fork is independent of Windscribe.

## Build and install

Use Java 21 to run Gradle and an Android SDK with API 36. Gradle installs the pinned NDK if its SDK license is already accepted. Restore the verified Xray dependencies before building a fresh checkout:

```powershell
./xray/fetch-runtime.ps1
$env:JAVA_HOME = 'C:/Program Files/Android/Android Studio/jbr'
$env:ANDROID_HOME = 'C:/Users/your-name/AppData/Local/Android/Sdk'
./gradlew.bat :mobile:assembleFdroidDebug -PabiFilter=arm64-v8a
adb install -r mobile/build/outputs/apk/fdroid/debug/mobile-fdroid-debug.apk
adb shell am start -n com.apexscribe.android/com.windscribe.mobile.ui.AppStartActivity
```

Omit `abiFilter` for all bundled architectures. This provider build excludes the unsupported WireGuard native build. The original source modules remain available. Google/F-Droid billing and Windscribe account APIs are not used by the ApexGuard adapter.

The stock welcome buttons launch fresh provider-hosted browser login, registration, or Google sign-in. The callback exchanges its one-time code only at the validated gateway. AndroidKeyStore encrypts the access/refresh token pair; logout invalidates pending requests and removes local credentials. Account availability does not imply a Windscribe subscription or data quota.

Windscribe account editing/billing, upgrades, quotas, vouchers, referrals, R.O.B.E.R.T., static IPs, custom-profile tabs, IP rotation/pinning, news, emergency connection, support uploads, and service marketing links are hidden. Stale navigation/deep links cannot open those screens. Local themes, favorites, languages, network preferences, log viewing/export, and software-license attribution remain available. No replacement marketing copy or custom screens are introduced.

## VPN and split tunneling

The grant determines the actual protocol. An invalid or missing Xray link can use IKEv2 credentials from that same grant. Native startup alone does not report Connected: an HTTPS IP request must succeed through the VPN network.

Both backends apply the existing inclusive/exclusive application preferences and retain the client UID for tunnel verification. Xray applies LAN bypass and excluded IP/domain routes. IKEv2 requires the provider certificate DN for single-label `net1.ch` gateways, with CA/signature checks enabled; other domains retain exact hostname certificate checks. IKEv2 uses server DNS; Xray sends default or plain custom DNS through VLESS. Encrypted custom DNS requires the upstream ctrld native engine and currently fails through the existing generic connection error in this provider build.

Android app exclusions bypass the entire VPN, including its IP-family policy. Android's VPN API cannot impose a global IPv6 firewall on excluded apps. Destination exclusions use the stock Android 13+ route-exclusion API. These differ from the privileged desktop firewall.

The include/exclude selector controls applications. IPs, IPv4 CIDRs, and hostnames always form a bypass list, including when an app is included. Hostnames use cached IPv4 addresses; unresolved entries add no bypass route until resolved, and a manual refresh updates the cache. Shared destination addresses can bypass other names on the same IP. There is no destination-inclusion or wildcard-domain mode. Reconnect after changing routing preferences. IKEv2 LAN bypass excludes private IPv4 ranges; Xray excludes directly connected networks and local discovery/broadcast routes.

## Verification

Run the focused tests and build the hardware test APK:

```powershell
./gradlew.bat :base:testFdroidDebugUnitTest --tests '*Apex*' --tests '*Xray*Test' --tests '*ProtectedDialerTest' --tests '*WindVpnControllerForceDisconnectTest' -PabiFilter=arm64-v8a
./gradlew.bat :mobile:assembleFdroidDebugAndroidTest -PabiFilter=arm64-v8a
adb install -r mobile/build/outputs/apk/androidTest/fdroid/debug/mobile-fdroid-debug-androidTest.apk
adb shell am instrument -w -e class com.windscribe.mobile.ApexDeviceSmokeTest,com.windscribe.mobile.XrayNativeSmokeTest com.apexscribe.android.test/androidx.test.runner.AndroidJUnitRunner
```

After signing in through the stock app and granting Android VPN permission, the opt-in live test uses a second app UID to measure real split routing. The probe has no launcher or UI and is excluded from normal builds:

```powershell
./gradlew.bat :networkprobe:assembleDebug -PincludeNetworkProbe=true
adb install -r networkprobe/build/outputs/apk/debug/networkprobe-debug.apk
adb shell am instrument -w -r -e class com.windscribe.mobile.ApexLiveTunnelTest -e runLiveTunnelTests true com.apexscribe.android.test/androidx.test.runner.AndroidJUnitRunner
adb uninstall com.apexscribe.networkprobe
```

The default live test covers both protocols and five app routing modes. Add `-e routingCases extended` for 26 cases per protocol: application modes, IP, `/32`, `/24`, resolved hostnames combined with selected/unselected apps in both app modes, disabled split with saved exclusions, and uncached/stale/refreshed hostnames. Supplying `-e lanIp <private-address> -e lanPort <listening-port>` adds LAN bypass off/on, for 56 total cases across both protocols. Use a reachable TCP listener that echoes the probe's ASCII nonce line unchanged, including its newline. A TCP handshake alone cannot prove remote reachability through a TUN proxy. The HTTPS probe pins its tested IPv4 destination while preserving platform TLS verification and ordinary per-UID routing.

Each case checks the physical route separately and reconnects through the production controller. Tests restore preferences, remove only their inserted destination rows, disconnect, and restore screen wake behavior. Optional `protocols`, `modes`, and `cityId` arguments select a subset. Real credentials are entered only through hosted sign-in, never passed as test arguments.

The connected Samsung SM-T725 runs Android 14. The debug APK builds and installs. All 49 focused provider/backend and navigation-policy JVM tests pass and run in CI. All four device smoke tests pass: stock activity startup, real provider HTTPS metadata, strongSwan native library loading, and the shipped Xray raw/gRPC core with authenticated loopback SOCKS startup and shutdown. Broader Windows runs retain two unchanged upstream failures: OpenVPN newline parsing and filename-separator tests assume Linux behavior.

Hosted login and session persistence pass on the tablet. Both IKEv2 and Xray pass all 56 routing cases described above: 52 public-destination cases and four LAN cases using an independent nonce echo endpoint. Direct Xray → IKEv2 → Xray switching also passes. Each case verifies tunneled HTTPS traffic and a separate-UID probe; bypassed traffic must match the physical address, while tunneled traffic must differ. Provider exits may use different NAT addresses for different destinations. These are the supported routing equivalence classes on this Android 14 device; IPv6 traffic, other Android versions, arbitrary networks, and every possible application/destination list have not been exhaustively tested.

## Source and licenses

The [desktop ApexScribe project](https://github.com/neoyarus/ApexScribe) supplies the provider contract. [UPSTREAM.md](UPSTREAM.md) preserves the original mobile documentation. Retain [LICENSE.md](LICENSE.md) and third-party notices; native runtime notices are included in the APK assets. Build/signing credentials and account tokens stay outside source control.
