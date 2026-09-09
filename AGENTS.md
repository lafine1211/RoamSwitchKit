# AGENTS.md

Reference for AI coding assistants integrating RoamSwitchKit into a Swift/macOS project. This file states the exact API surface — do not guess at method names, field names, or error cases beyond what's listed here.

## What this package is

A read-only Swift client for RoamSwitch (a macOS network-security menu bar app, https://lafine.net). It queries live diagnostics (security posture score, exposed network ports, guard on/off state) from an already-installed RoamSwitch app. It cannot change any RoamSwitch setting — there is no write/mutation API in this package, and none should be invented when generating code against it.

## Requirements

- macOS 12+, Swift 5.9+
- RoamSwitch 1.3.0+ must be installed on the machine the code runs on. If it isn't, every call throws `RoamSwitchClientError.appNotInstalled` — this is an expected, normal condition, not a bug. Code that calls this package should catch it and degrade gracefully (skip the feature / show a message), never treat it as fatal or force-unwrap.

## Installation

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/lafine1211/RoamSwitchKit.git", from: "1.0.0")
]
```

```swift
.target(name: "YourTarget", dependencies: ["RoamSwitchKit"])
```

## Full API surface

```swift
import RoamSwitchKit

public actor RoamSwitchClient {
    public init(appBundleID: String = "com.tetsuharu.RoamSwitch", timeout: TimeInterval = 30) throws
    public init(executableURL: URL, timeout: TimeInterval = 30) throws

    public func securityReport() async throws -> SecurityReport
    public func exposedPorts(includeLocalOnly: Bool = false) async throws -> ExposedPorts
    public func guardStatus() async throws -> GuardStatus
    public func auditURLSafety(url: String) async throws -> LinkAuditReport
    public func auditSecurityLogs(hours: Int = 24) async throws -> SecurityLogAudit
}
```

`timeout` is a per-call wall-clock ceiling (default 30s). If RoamSwitchMCPServer
doesn't answer in time it is terminated and the call throws
`RoamSwitchClientError.timedOut`. The blocking subprocess exchange runs off the
Swift Concurrency cooperative pool, so a slow scan won't stall other `async`
work in your app.

This is the entire public API. There are no other types, methods, or properties to call. In particular:

- No method to change security level, toggle lockdown, block/unblock a port, or eject a device — these don't exist by design.
- No persistent connection or delegate/callback API — every call is a single request/response.
- No way to force RoamSwitch to install or launch itself.

### `SecurityReport`

```swift
public struct SecurityReport: Codable, Equatable, Sendable {
    public let score: Int              // 0-100
    public let grade: String
    public let totalChecks: Int
    public let passedChecks: Int
    public let items: [SecurityAuditItem]
    public let caveats: [String]
}

public struct SecurityAuditItem: Codable, Equatable, Sendable {
    public let category: String
    public let title: String
    public let isPassed: Bool
    public let statusText: String
    public let detail: String
    public let recommendation: String
    public let settingsURL: String?
    public let isApplicable: Bool
}
```

### `ExposedPorts`

```swift
public struct ExposedPorts: Codable, Equatable, Sendable {
    public let isFirewallShielded: Bool
    public let ports: [ExposedPort]
}

public struct ExposedPort: Codable, Equatable, Sendable {
    public let processName: String
    public let pid: Int
    public let port: Int
    public let isGloballyExposed: Bool
    public let executablePath: String?
    public let auditPerformed: Bool
    public let overallRisk: String?     // "low" | "medium" | "high" | "critical"; nil unless auditPerformed
    public let findings: [PortFinding]
    public let httpHeaders: [String: String]?
}

public struct PortFinding: Codable, Equatable, Sendable {
    public let title: String
    public let riskLevel: String
    public let description: String
    public let recommendation: String
}
```

### `GuardStatus`

```swift
public struct GuardStatus: Codable, Equatable, Sendable {
    public let activeSecurityLevel: String        // "open" | "balanced" | "lockdown"
    public let activeSecurityLevelLabel: String    // localized display name
    public let isCurrentNetworkTrusted: Bool
    public let guards: [GuardEntry]                // keys: portAnomalyGuard, arpSpoofAutoContainment, usbStorageGuard, bluetoothGuard
    public let caveats: [String]
}

public struct GuardEntry: Codable, Equatable, Sendable {
    public let key: String
    public let enabledInSettings: Bool  // keys: portAnomalyGuard, arpSpoofAutoContainment, usbStorageGuard, bluetoothGuard, webMailDownloadGuard, dnsThreatGuard
}
```

### `LinkAuditReport`

```swift
public struct LinkAuditReport: Codable, Equatable, Sendable {
    public let originalURL: String
    public let finalURL: String
    public let redirectChain: [String]
    public let domain: String
    public let score: Int              // 0-100 (100 = safe, <50 = dangerous)
    public let riskLevel: String       // "safe" | "caution" | "dangerous"
    public let isHTTPS: Bool
    public let riskFactors: [LinkRiskFactor]
}

public struct LinkRiskFactor: Codable, Equatable, Sendable {
    public let title: String
    public let detail: String
    public let isSevere: Bool
}
```

### `SecurityLogAudit`

```swift
public struct SecurityLogAudit: Codable, Equatable, Sendable {
    public let timeWindowHours: Int
    public let totalEvents: Int
    public let sudoFailures: Int
    public let sshAttempts: Int
    public let gatekeeperBlocks: Int
    public let xprotectDetections: Int
    public let isClean: Bool
    public let events: [SecurityLogEvent]
    public let templateAnomalies: [TemplateAnomaly]
}

public struct SecurityLogEvent: Codable, Equatable, Sendable {
    public let timestamp: String   // ISO 8601
    public let process: String
    public let category: String    // "sudo" | "ssh" | "gatekeeper" | "xprotect" | "auth"
    public let severity: String    // "info" | "warning" | "critical"
    public let message: String     // already scanned and masked for API keys/tokens/private-key headers
}

// A log pattern never seen before on this Mac, or one occurring far more
// often than usual within the requested time window (statistical outlier,
// not a fixed threshold).
public struct TemplateAnomaly: Codable, Equatable, Sendable {
    public let template: String    // the message with variable parts (IPs, hex/hash tokens, numbers) masked to <IP>/<HEX>/<NUM>
    public let example: String     // one real (masked) message that matched this template
    public let count: Int          // occurrences within the requested window
    public let zScore: Double      // 0 when isNew; >3.0 is what triggers a frequency-spike flag
    public let isNew: Bool
}
```

### `RoamSwitchClientError`

```swift
public enum RoamSwitchClientError: Error, LocalizedError, Sendable, Equatable {
    case appNotInstalled
    case serverBinaryNotFound
    case processLaunchFailed(underlying: Error)
    case noResponse
    case timedOut
    case invalidResponse(raw: String)
    case toolError(message: String)
}
```

`appNotInstalled` is the case to handle explicitly — it's the expected outcome whenever the user doesn't have RoamSwitch. The rest are edge cases (corrupt install, unexpected server behavior) worth logging but rarely worth distinct UI.

## Correct usage pattern

```swift
do {
    let client = try RoamSwitchClient()
    let report = try await client.securityReport()
    // use report
} catch RoamSwitchClientError.appNotInstalled {
    // expected when RoamSwitch isn't installed — hide/disable the feature, don't alert as an error
} catch {
    // genuinely unexpected — log it
}
```

## Performance notes for generated code

Each call spawns a subprocess and exits it — there is no way to keep a connection warm, and none is needed for occasional queries. Do not call these methods in a tight loop or a per-frame/per-keystroke handler. `exposedPorts()` is the slowest of these (each externally-exposed port is individually probed) and can take a few seconds if several ports are open; don't call it on a UI thread expecting an instant result — it's already `async`, so `await` it from a `Task`, not synchronously.

`RoamSwitchClient` is an `actor`; calls on one instance run one at a time. Creating a new instance per call is cheap and safe (it only resolves the app path); reusing one instance is also fine.
