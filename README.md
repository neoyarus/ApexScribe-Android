# ApexScribe Android

ApexGuard client built from the official Windscribe Android application. The phone and tablet interface, assets, layouts, and localized strings remain upstream. Existing login, location, connection, protocol, and split-tunneling controls use the ApexGuard provider integration. The installed package is `com.apexscribe.android`, so it can coexist with Windscribe.

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

## VPN and split tunneling

The grant determines the actual protocol. An invalid or missing Xray link can use IKEv2 credentials from that same grant. Native startup alone does not report Connected: an HTTPS IP request must succeed through the VPN network.

Both backends apply the existing inclusive/exclusive application preferences and retain the client UID for tunnel verification. Xray applies LAN bypass and excluded IP/domain routes. IKEv2 uses server DNS; Xray sends default or plain custom DNS through VLESS. Encrypted custom DNS requires the upstream ctrld native engine and currently fails through the existing generic connection error in this provider build.

Android app exclusions bypass the entire VPN, including its IP-family policy. Android's VPN API cannot impose a global IPv6 firewall on excluded apps. Destination exclusions use the stock Android 13+ route-exclusion API. These differ from the privileged desktop firewall.

## Verification

Run the focused tests and build the hardware test APK:

```powershell
./gradlew.bat :base:testFdroidDebugUnitTest --tests '*Apex*' --tests '*Xray*Test' --tests '*ProtectedDialerTest' --tests '*WindVpnControllerForceDisconnectTest' -PabiFilter=arm64-v8a
./gradlew.bat :mobile:assembleFdroidDebugAndroidTest -PabiFilter=arm64-v8a
adb install -r mobile/build/outputs/apk/androidTest/fdroid/debug/mobile-fdroid-debug-androidTest.apk
adb shell am instrument -w -e class com.windscribe.mobile.ApexDeviceSmokeTest,com.windscribe.mobile.XrayNativeSmokeTest com.apexscribe.android.test/androidx.test.runner.AndroidJUnitRunner
```

The connected Samsung SM-T725 runs Android 14. The debug APK builds and installs. The focused provider/backend suite passes 33 tests. All four device smoke tests pass: stock activity startup, real provider HTTPS metadata, strongSwan native library loading, and the shipped Xray raw/gRPC core with authenticated loopback SOCKS startup and shutdown. The broader Windows JVM suite passes 210 of 212 tests; unchanged upstream OpenVPN newline parsing and filename-separator tests assume Linux behavior.

Authenticated login, live IKEv2/Xray traffic, and application bypass exit-IP comparisons remain pending tablet unlock and account sign-in. The tablet currently displays "Device locked by admin". Keep the integration draft until those checks pass.

## Source and licenses

The [desktop ApexScribe project](https://github.com/neoyarus/ApexScribe) supplies the provider contract. [UPSTREAM.md](UPSTREAM.md) preserves the original mobile documentation. Retain [LICENSE.md](LICENSE.md) and third-party notices; native runtime notices are included in the APK assets. Build/signing credentials and account tokens stay outside source control.
