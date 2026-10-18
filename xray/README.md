# Android Xray runtime

The app links official upstream release artifacts; `fetch-runtime.ps1` downloads
and checks SHA256 before installing either dependency into `libs/`.

| Component | Pinned release | SHA256 |
| --- | --- | --- |
| [AndroidLibXrayLite](https://github.com/2dust/AndroidLibXrayLite/releases/tag/v26.10.17) | v26.10.17, libv2ray.aar | fd6cb61fed873e465c3064327dffbcb22dc3fd78260d162ec9e868db2582495f |
| [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel/releases/tag/2.19.0) | 2.19.0, hev-socks5-tunnel.aar | fbbf014c1c4c6d1e0922db88542abd9dc726600473bdfdc8039ed157b4ba02b0 |

Hashes match the release assets' GitHub API `digest` fields and were independently
checked after downloading. Both AARs include arm64-v8a, armeabi-v7a, x86 and
x86_64. Xray requires Android API 24; the official hev AAR requires API 29.
The application must use API 29 or newer for these exact artifacts.

Upstream source/build instructions and licenses:

- [Xray wrapper source](https://github.com/2dust/AndroidLibXrayLite/tree/v26.10.17),
  [license](https://github.com/2dust/AndroidLibXrayLite/blob/v26.10.17/LICENSE),
  [pinned Xray core dependency](https://github.com/2dust/AndroidLibXrayLite/blob/v26.10.17/go.mod).
- [hev source and build instructions](https://github.com/heiher/hev-socks5-tunnel/tree/2.19.0),
  [MIT license](https://github.com/heiher/hev-socks5-tunnel/blob/2.19.0/LICENSE),
  [JNI API](https://github.com/heiher/hev-socks5-tunnel/blob/2.19.0/android/hev/htproxy/TProxyService.java).

`XrayVpnService` establishes Android's TUN and gives its descriptor to hev. hev
forwards TCP and UDP through an authenticated loopback Xray SOCKS inbound.
VLESS/REALITY raw and gRPC transports use Xray's `sockopt.dialerProxy` to an
authenticated, endpoint-restricted loopback SOCKS listener in `ProtectedDialer`.
That listener creates the actual upstream socket and requires
`VpnService.protect(socket)` to succeed before connecting. The Xray wrapper no
longer exposes a socket-protection callback, so this explicit dialer path is
necessary; excluding the app UID would invalidate its tunnel connectivity test.

The grant endpoint is resolved before establishing the TUN. DNS queries from apps
go through the SOCKS/VLESS tunnel. Stock custom plain DNS uses the selected IP.
The ApexGuard build disables the stock ctrld native runtime, so selecting a custom
encrypted resolver aborts connection using the existing generic connection error;
it never substitutes plaintext DNS or advertises an absent local listener.
Native startup readiness is separate from the backend's
Internet connectivity check. No credentials or generated Xray JSON are persisted.
The temporary hev YAML contains only ephemeral loopback credentials and is deleted
when the service stops. The service refuses sticky restarts with stale grants.

Stock inclusive and exclusive app preferences are applied by Android's VPN
builder. The app UID is retained in an inclusive VPN for DNS and verification;
an empty inclusive selection therefore cannot accidentally route every app.
Stock excluded IP/domain routes are applied through `ExcludedIpHolder`.
The stock LAN bypass switch excludes directly connected physical-network routes,
local broadcast and discovery multicast. CIDR subtraction implements the same
routing behavior on API 29–32, before Android's `excludeRoute` API is available.

Native JNI classes are referenced by name, so release shrinking must retain
`hev.htproxy.TProxyService`, `libv2ray.**`, and `go.**`.
