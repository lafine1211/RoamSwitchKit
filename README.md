# RoamSwitchKit

A read-only Swift client for [RoamSwitch](https://lafine.net)'s local Mac network security diagnostics.

[![Swift](https://img.shields.io/badge/Swift-5.9%2B-orange)](https://swift.org)
[![Platform](https://img.shields.io/badge/platform-macOS%2012%2B-lightgrey)](https://lafine.net)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What is RoamSwitch?

[**RoamSwitch**](https://lafine.net) is a macOS menu bar app that automatically defends your Mac's network boundary — the moment you join a coffee-shop Wi-Fi, a conference network, or any network you haven't explicitly trusted, it can tighten your firewall, watch for ARP spoofing, and flag dev servers or databases you forgot are listening on `0.0.0.0`. It ships free with a Pro tier for automated, no-click responses (auto-block on new listening ports, auto-containment on detected ARP spoofing, USB storage/Bluetooth guards).

Concretely, RoamSwitch continuously computes:

- **Network trust** — is the current Wi-Fi/gateway one you've marked trusted, and what security level (Open / Balanced / Lockdown) is currently active
- **ARP spoofing** — gateway MAC fingerprint changes that indicate a man-in-the-middle attempt
- **Exposed ports** — every TCP port listening beyond `localhost`, cross-referenced against a database of commonly-misconfigured services (Redis, MongoDB, Elasticsearch, Docker, Memcached, dev servers like `next dev`/Vite/`python -m http.server`, and local AI inference servers like Ollama:11434, LM Studio:1234, Gradio:7860, vLLM:8000) and probed for risky HTTP responses
- **A 10-point local security posture score** — FileVault, SIP, Gatekeeper, auto-update, XProtect, firewall state, Wi-Fi encryption, ARP status, exposed ports, and guard configuration (including AI Pickle model download guard and confidential secret leak prevention)

RoamSwitch already exposes this same data to AI assistants (Claude Desktop, Claude Code, and other [MCP](https://modelcontextprotocol.io)-compatible clients) via a bundled read-only MCP server — see [lafine.net/mcp-setup](https://lafine.net/mcp-setup.html). **RoamSwitchKit is the same interface, wrapped for Swift code instead of an AI client**: it lets your own macOS app or script ask "is this Mac's network safe right now?" and get back the exact data RoamSwitch itself computed, without reimplementing ARP inspection, port scanning, or Wi-Fi security checks yourself.

Typical uses: a sync app pausing background transfers on an untrusted network, a password manager tightening auto-lock on Open Wi-Fi, a dev-tools app warning when it's about to bind a server on `0.0.0.0`, or a Shortcuts/automation workflow that reacts to network trust changes.

## Design principles

- **Read-only, always.** RoamSwitchKit can query RoamSwitch's current diagnostics. It has no API to change RoamSwitch's security level, toggle lockdown, isolate a port, or eject a device — that surface simply doesn't exist in this package. Any app linking RoamSwitchKit has no way to alter another user's protection state; only RoamSwitch's own UI, driven by the user, can do that. This is a deliberate scope limit, not a v1 gap: giving third-party code write access to a security tool's protections would undermine the trust model for everyone.
- **Fully local, zero telemetry.** Every call launches RoamSwitch's bundled `RoamSwitchMCPServer` binary as a subprocess and talks to it over stdio. There are no network requests anywhere in this package's code — nothing is sent anywhere, by RoamSwitchKit or by RoamSwitch itself.
- **No new attack surface.** RoamSwitchKit doesn't open a socket, register a service, or listen for anything. It spawns a process, writes a request to its stdin, reads one response from its stdout, and lets the process exit.

## Requirements

- macOS 12+
- Swift 5.9+ (Xcode 15+)
- [RoamSwitch](https://lafine.net) 1.3.0 or later installed on the machine your code runs on (RoamSwitchMCPServer, the binary this package talks to, first shipped in that release)

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
let status = try await client.guardStatus()
print(status.activeSecurityLevelLabel, status.isCurrentNetworkTrusted)

// Inspect email links, shortened URLs, or suspicious web domains for
// phishing, Unicode homograph spoofing, and brand imitation (Zero Telemetry).
let urlReport = try await client.auditURLSafety(url: "https://apple.com.login-verify.xyz")
print(urlReport.score, urlReport.riskLevel) // e.g. 20, "dangerous"

// macOS Unified Log security events (sudo/SSH/Gatekeeper/XProtect) over the
// last N hours, plus any log-pattern anomalies (a pattern never seen before
// on this Mac, or one occurring far more often than usual this window).
// Every message is scanned for API keys/tokens/private-key headers and
// masked before it ever leaves RoamSwitch.
let logAudit = try await client.auditSecurityLogs(hours: 24)
for anomaly in logAudit.templateAnomalies where anomaly.isNew {
    print("New log pattern: \(anomaly.template)")
}
```

All calls are `async throws` and can fail with `RoamSwitchClientError` — most commonly `.appNotInstalled` if RoamSwitch isn't present. Handle that case gracefully (e.g. hide the feature, or point the user to lafine.net) rather than treating it as fatal.

## How it works

`RoamSwitchClient` doesn't talk to a running RoamSwitch process directly. Each call:

1. Resolves RoamSwitch's install location via `NSWorkspace.urlForApplication(withBundleIdentifier:)` (default bundle ID `com.tetsuharu.RoamSwitch`) and locates `Contents/MacOS/RoamSwitchMCPServer` inside it.
2. Launches that binary as a fresh subprocess.
3. Sends the standard MCP handshake (`initialize`, `notifications/initialized`) followed by a `tools/call` request, as newline-delimited JSON-RPC 2.0 over the subprocess's stdin — the same protocol RoamSwitch speaks to Claude Desktop/Code and other MCP clients.
4. Reads the matching response line from stdout, decodes its JSON payload into a typed Swift struct, and lets the subprocess exit.

This is stateless by design: no persistent connection, no daemon, nothing left running between calls. Each `RoamSwitchClient` method call has its own subprocess lifetime, which also means calls have process-launch overhead (tens of milliseconds) plus whatever the diagnostic itself takes — `exposedPorts()` in particular can take a couple of seconds if there are several externally-exposed ports to audit, since each is probed individually.

`RoamSwitchClient` is a Swift `actor`, so calls on the same instance are serialized; create one instance and reuse it, or create one per call — both are safe.

## API reference

### `RoamSwitchClient`

```swift
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

- `init(appBundleID:timeout:)` — resolves and validates the RoamSwitch install. Override `appBundleID` only for testing against a differently-identified build.
- `init(executableURL:timeout:)` — directly targets a specific `RoamSwitchMCPServer` binary (useful for debugging, testing, or non-standard install paths).
- `timeout` — per-call wall-clock ceiling (default 30s). On expiry the subprocess is terminated and the call throws `.timedOut`. The blocking exchange runs off the Swift Concurrency cooperative pool, so it won't stall other `async` work.
- `securityReport()` — runs RoamSwitch's full local Mac security audit.
- `exposedPorts(includeLocalOnly:)` — lists listening TCP ports. Ports exposed beyond localhost are always fully audited; pass `includeLocalOnly: true` to also include localhost-only ports (returned without the slower per-port audit).
- `guardStatus()` — current active security level, trusted-network status, and each optional guard's on/off state.
- `auditURLSafety(url:)` — analyzes an email link or web URL for phishing threats, Unicode homograph spoofing, brand subdomain deception, and high-risk TLDs (Zero Telemetry).
- `auditSecurityLogs(hours:)` — audits macOS Unified Log security events (sudo/SSH/Gatekeeper/XProtect) over the given window and flags log-pattern anomalies (new patterns / frequency spikes). Every message is masked for API keys/tokens/private-key headers before it leaves RoamSwitch.

### `SecurityReport`

| Field | Type | Description |
|---|---|---|
| `score` | `Int` | 0–100 overall score |
| `grade` | `String` | Letter grade derived from `score` |
| `totalChecks` | `Int` | Number of audit items |
| `passedChecks` | `Int` | Number of items that passed |
| `items` | `[SecurityAuditItem]` | One entry per check |
| `caveats` | `[String]` | Notes on anything this tool couldn't fully verify (e.g. Wi-Fi SSID unreadable without Location Services permission, which a bare CLI process can't hold) |

`SecurityAuditItem`: `category`, `title`, `isPassed: Bool`, `statusText`, `detail`, `recommendation`, `settingsURL: String?`, `isApplicable: Bool`.

### `ExposedPorts`

| Field | Type | Description |
|---|---|---|
| `isFirewallShielded` | `Bool` | Whether the active security level currently blocks all inbound connections |
| `ports` | `[ExposedPort]` | One entry per listening TCP port |

`ExposedPort`: `processName`, `pid: Int`, `port: Int`, `isGloballyExposed: Bool`, `executablePath: String?`, `auditPerformed: Bool`, `overallRisk: String?` (`"low"` / `"medium"` / `"high"` / `"critical"`, present only when `auditPerformed`), `findings: [PortFinding]`, `httpHeaders: [String: String]?`.

`PortFinding`: `title`, `riskLevel: String`, `description`, `recommendation`.

### `GuardStatus`

| Field | Type | Description |
|---|---|---|
| `activeSecurityLevel` | `String` | Raw level identifier (`"open"` / `"balanced"` / `"lockdown"`) |
| `activeSecurityLevelLabel` | `String` | Localized display name |
| `isCurrentNetworkTrusted` | `Bool` | Whether the current gateway matches a saved trusted network |
| `guards` | `[GuardEntry]` | One entry per optional guard: `portAnomalyGuard`, `arpSpoofAutoContainment`, `usbStorageGuard`, `bluetoothGuard`, `webMailDownloadGuard`, `dnsThreatGuard` |
| `caveats` | `[String]` | Notes — in particular, that `enabledInSettings` reflects the Settings toggle only; actual guard behavior also depends on RoamSwitch Pro license state, which this tool (running as a separate process) can't verify |

`GuardEntry`: `key: String`, `enabledInSettings: Bool`.

### `LinkAuditReport`

| Field | Type | Description |
|---|---|---|
| `originalURL` | `String` | The URL as passed in |
| `finalURL` | `String` | The URL after following any redirects |
| `redirectChain` | `[String]` | Every URL hop between `originalURL` and `finalURL` |
| `domain` | `String` | The final destination's domain |
| `score` | `Int` | 0–100 (100 = safe, below 50 = dangerous) |
| `riskLevel` | `String` | `"safe"` / `"caution"` / `"dangerous"` |
| `isHTTPS` | `Bool` | Whether the final URL uses HTTPS |
| `riskFactors` | `[LinkRiskFactor]` | Specific findings — Unicode homograph spoofing, brand-name subdomain deception, high-risk TLDs, plaintext HTTP, etc. |

`LinkRiskFactor`: `title`, `detail`, `isSevere: Bool`.

### `SecurityLogAudit`

| Field | Type | Description |
|---|---|---|
| `timeWindowHours` | `Int` | The requested window, echoed back |
| `totalEvents` | `Int` | `events.count` |
| `sudoFailures` | `Int` | Sudo authentication failures in the window |
| `sshAttempts` | `Int` | SSH connection attempts in the window |
| `gatekeeperBlocks` | `Int` | Gatekeeper blocks in the window |
| `xprotectDetections` | `Int` | XProtect malware detections in the window |
| `isClean` | `Bool` | No sudo failures, Gatekeeper blocks, or XProtect detections |
| `events` | `[SecurityLogEvent]` | Individual matched log events, newest first |
| `templateAnomalies` | `[TemplateAnomaly]` | Log patterns flagged as new or a frequency outlier — see below |

`SecurityLogEvent`: `timestamp: String` (ISO 8601), `process`, `category: String` (`"sudo"` / `"ssh"` / `"gatekeeper"` / `"xprotect"` / `"auth"`), `severity: String` (`"info"` / `"warning"` / `"critical"`), `message` (already scanned and masked for API keys/tokens/private-key headers).

`TemplateAnomaly`: a log pattern never seen before on this Mac, or one occurring far more often than usual within the requested window (a statistical outlier, not a fixed threshold) — `template` (the message with variable parts like IPs/hex/numbers masked to `<IP>`/`<HEX>`/`<NUM>`), `example` (one real, masked message matching this template), `count: Int`, `zScore: Double` (0 when `isNew`; >3.0 is what triggers a frequency-spike flag), `isNew: Bool`.

### `RoamSwitchClientError`

| Case | Meaning |
|---|---|
| `.appNotInstalled` | No app with the given bundle ID is registered with Launch Services |
| `.serverBinaryNotFound` | RoamSwitch is installed but predates 1.3.0 (no `RoamSwitchMCPServer` in the bundle) |
| `.processLaunchFailed(underlying:)` | The subprocess itself failed to launch |
| `.noResponse` | The subprocess's stdout closed before a response arrived |
| `.timedOut` | The subprocess didn't respond within `timeout` and was terminated |
| `.invalidResponse(raw:)` | A response was received but wasn't valid/expected JSON-RPC |
| `.toolError(message:)` | The server returned a JSON-RPC error or a tool result with `isError: true` |

All cases conform to `LocalizedError`, so `error.localizedDescription` gives a human-readable message.

## Compatibility note

The JSON returned by RoamSwitch's diagnostic tools is the actual contract between this package and the app. `Sources/RoamSwitchKit/Models.swift` mirrors that shape independently — RoamSwitchKit is a separate, public repository from the private RoamSwitch app repo, so it can't share Swift types directly. If a future RoamSwitch release changes the response shape, this package's models are updated to match in lockstep; pin a version if that matters to you.

## For AI coding assistants

[AGENTS.md](AGENTS.md) has the exact API surface in a compact, machine-oriented format — point Claude Code, Cursor, Copilot, etc. at it when integrating this package to avoid hallucinated method/field names.

This is picked up automatically only if your assistant is working directly inside this repository. If you've added RoamSwitchKit as a dependency in a different project, your assistant won't discover it on its own — paste this URL when asking it to integrate the package: `https://github.com/lafine1211/RoamSwitchKit/blob/main/AGENTS.md`.

## License

MIT — see [LICENSE](LICENSE).
