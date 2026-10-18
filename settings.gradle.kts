include(":openvpn")
include(":strongswan")
include(":base")
include(":mobile")
include(":tv")
include(":common")
include(":wgtunnel")
include(":baselineprofile")

// A separate UID for opt-in, on-device split-routing verification only.
if (providers.gradleProperty("includeNetworkProbe").orNull == "true") {
    include(":networkprobe")
}
