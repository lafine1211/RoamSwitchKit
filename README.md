# RoamSwitchKit

A read-only Swift client for [RoamSwitch](https://lafine.net)'s local Mac network security diagnostics.

RoamSwitch is a macOS menu bar app that monitors Wi-Fi trust, ARP spoofing, and exposed network ports, and can automatically tighten your firewall on untrusted networks. RoamSwitchKit lets your own app or script ask RoamSwitch "is this Mac's network safe right now?" and get back the same data RoamSwitch itself computes — without reimplementing ARP inspection, port scanning, or Wi-Fi security checks yourself.

## What this is (and isn't)

- **Read-only.** RoamSwitchKit can query RoamSwitch's current diagnostics. It cannot change RoamSwitch's security level, toggle lockdown, isolate a port, or eject a device. Any app linking this package has no way to alter another user's protection state — only RoamSwitch's own UI, driven by the user, can do that.
- **Fully local.** Every call launches RoamSwitch's bundled `RoamSwitchMCPServer` binary as a subprocess and talks to it over stdio. No network requests, no telemetry, nothing leaves the Mac.
- **Requires RoamSwitch 1.3.0+ installed.** This package is a client for the app, not a standalone security scanner — if RoamSwitch isn't installed, calls throw `RoamSwitchClientError.appNotInstalled`.

## Installation

Add it to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/lafine1211/RoamSwitchKit.git", from: "1.0.0")
]
```

## Usage

```swift
import RoamSwitchKit

let client = try RoamSwitchClient()

// Full security audit (FileVault, SIP, Gatekeeper, firewall, Wi-Fi
// encryption, ARP spoofing, exposed ports — scored 0-100 with per-item
// recommendations for anything failing).
let report = try await client.securityReport()
print(report.score, report.grade)

// Every port listening beyond localhost, audited for known-dangerous
// services and risky HTTP responses.
let ports = try await client.exposedPorts()
for port in ports.ports where port.overallRisk == "high" {
    print("\(port.processName) on port \(port.port): \(port.findings.first?.recommendation ?? "")")
}

// Whether RoamSwitch's optional Pro auto-response guards are turned on,
// and whether the current network is in the user's trusted list.
let guards = try await client.guardStatus()
print(guards.activeSecurityLevelLabel, guards.isCurrentNetworkTrusted)
```

All three calls are `async throws` and can fail with `RoamSwitchClientError` — most commonly `.appNotInstalled` if RoamSwitch isn't present. Handle that case gracefully (e.g. hide the feature) rather than treating it as fatal.

## Compatibility note

The JSON returned by RoamSwitch's diagnostic tools is the actual contract between this package and the app. This package's `Models.swift` mirrors that shape independently (RoamSwitchKit is a separate, public repository from the private RoamSwitch app repo, so it can't share Swift types directly). If a future RoamSwitch release changes the response shape, this package's models are updated to match in lockstep — pin a version if that matters to you.

## License

MIT — see [LICENSE](LICENSE).
