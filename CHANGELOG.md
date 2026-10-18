# Changelog

## Unreleased — ApexScribe Android

- Connect the stock Windscribe phone/tablet interface to ApexGuard hosted login, account session, locations, and VPN grants.
- Add strongSwan IKEv2 and pinned native Xray VLESS/REALITY raw/gRPC support, with encrypted tokens and physical-network control requests.
- Apply stock app split tunneling, destination exclusions, and LAN bypass; require verified tunneled HTTPS before showing Connected.
- Fix provider certificate identity compatibility, protected-socket initialization, relay shutdown exceptions, and Android VPN service teardown.
- Hide Windscribe-only account/billing, R.O.B.E.R.T., referral, news, static/custom-server, emergency, support-upload, and service-marketing controls, including stale navigation routes. Preserve upstream components and localized copy for supported features, local log export, and licenses.
- Fix isolated-package log export, validate plain custom DNS before saving, and use validated provider coordinates for GPS spoofing.
- Verify both protocols with 56 live routing cases covering application include/exclude modes, IPv4/IP-prefix/hostname bypass, hostname cache states, disabled saved rules, and LAN bypass off/on. Verify direct protocol switching on a Samsung SM-T725 running Android 14, four hardware smoke tests, and 49 focused JVM tests.
