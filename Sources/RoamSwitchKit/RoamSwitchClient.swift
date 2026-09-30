import Foundation
import AppKit

/// Read-only access to RoamSwitch's local Mac network security diagnostics.
///
/// Every call launches RoamSwitch's bundled `RoamSwitchMCPServer` binary as
/// a short-lived subprocess and speaks the same JSON-RPC protocol RoamSwitch
/// exposes to AI clients (Claude Desktop, Claude Code, etc.) — this package
/// is just a typed Swift wrapper around that same read-only interface.
/// Nothing here can change RoamSwitch's settings, toggle lockdown, isolate
/// a port, or eject a device: only the app itself (or the user, in its UI)
/// can do that.
///
/// Requires RoamSwitch 1.3.0 or later to be installed — see
/// https://lafine.net.
public actor RoamSwitchClient {
    private let executableURL: URL
    private let timeout: TimeInterval

    /// Serializes the blocking subprocess exchange and, crucially, keeps it
    /// off the Swift Concurrency cooperative thread pool — a security scan can
    /// take several seconds, and blocking a cooperative thread that long can
    /// stall (or deadlock) unrelated `async` work in the host app.
    private let transportQueue = DispatchQueue(label: "net.lafine.roamswitchkit.transport", qos: .userInitiated)

    /// Tools that run active scans / heavy parsing get a longer ceiling than
    /// the caller's baseline `timeout`; cheap local-state reads get a shorter
    /// one so a wedged server fails fast.
    private enum TimeoutClass {
        case light, normal, heavy
        func effective(_ base: TimeInterval) -> TimeInterval {
            switch self {
            case .light: return min(base, 15)
            case .normal: return base
            case .heavy: return max(base, 120)
            }
        }
    }

    /// Server-side limits (kept in sync with RoamSwitchMCPServer).
    private static let maxLogHours = 168
    private static let maxListLimit = 200

    /// - Parameters:
    ///   - appBundleID: RoamSwitch's bundle identifier. Only override this for
    ///     testing against a differently-identified build. The resolved app
    ///     and its helper must still be signed by the RoamSwitch Team ID.
    ///   - timeout: Baseline wall-clock ceiling for a single call (heavy scans
    ///     use at least 120 s, light local reads at most 15 s). On expiry the
    ///     server and its child processes are killed and the call throws
    ///     `RoamSwitchClientError.timedOut`. Defaults to 30 seconds.
    ///   - allowEnvironmentOverride: Opt in to honoring the
    ///     `ROAMSWITCH_SERVER_PATH` environment variable. Always honored in
    ///     DEBUG builds; ignored otherwise unless this is `true`. The override
    ///     binary is signature-verified except in DEBUG builds.
    /// - Throws: `RoamSwitchClientError.appNotInstalled` if no app with this
    ///   bundle ID is registered with Launch Services,
    ///   `.serverBinaryNotFound` if the app is installed but predates 1.3.0,
    ///   or `.untrustedExecutable` if no candidate passes signature checks.
    public init(appBundleID: String = "com.tetsuharu.RoamSwitch",
                timeout: TimeInterval = 30,
                allowEnvironmentOverride: Bool = false) throws {
        self.timeout = timeout

        #if DEBUG
        let envOverrideAllowed = true
        let skipVerification = true
        #else
        let envOverrideAllowed = allowEnvironmentOverride
        let skipVerification = false
        #endif
        if envOverrideAllowed,
           let envPath = ProcessInfo.processInfo.environment["ROAMSWITCH_SERVER_PATH"],
           FileManager.default.isExecutableFile(atPath: envPath) {
            let url = URL(fileURLWithPath: envPath)
            if !skipVerification, !CodeSignatureVerifier.isSignedByRoamSwitch(at: url) {
                throw RoamSwitchClientError.untrustedExecutable
            }
            self.executableURL = url
            return
        }

        // Several apps can claim the same bundle ID (copies, look-alikes);
        // take the first one whose signature actually verifies.
        let candidates = NSWorkspace.shared.urlsForApplications(withBundleIdentifier: appBundleID)
        guard !candidates.isEmpty else {
            throw RoamSwitchClientError.appNotInstalled
        }
        var sawUnsigned = false
        var sawMissingBinary = false
        var chosen: URL?
        for appURL in candidates {
            let binaryURL = appURL.appendingPathComponent("Contents/MacOS/RoamSwitchMCPServer")
            guard FileManager.default.isExecutableFile(atPath: binaryURL.path) else {
                sawMissingBinary = true
                continue
            }
            // The helper must really live inside the app bundle (no symlink escape).
            let appPath = appURL.resolvingSymlinksInPath().path
            guard binaryURL.resolvingSymlinksInPath().path.hasPrefix(appPath + "/") else {
                sawUnsigned = true
                continue
            }
            let appOK = CodeSignatureVerifier.isSignedByRoamSwitch(at: appURL, extraRequirement: "identifier \"\(appBundleID)\"")
            let helperOK = CodeSignatureVerifier.isSignedByRoamSwitch(at: binaryURL)
            if appOK && helperOK {
                chosen = binaryURL
                break
            }
            sawUnsigned = true
        }
        guard let chosen else {
            throw sawUnsigned ? RoamSwitchClientError.untrustedExecutable
                              : (sawMissingBinary ? RoamSwitchClientError.serverBinaryNotFound : RoamSwitchClientError.appNotInstalled)
        }
        self.executableURL = chosen
    }

    /// Launches an explicit server binary.
    ///
    /// - Parameter verifySignature: When `true` (default) the binary must be
    ///   signed by the RoamSwitch Team ID, otherwise
    ///   `RoamSwitchClientError.untrustedExecutable` is thrown. Pass `false`
    ///   only for tests / local development builds.
    public init(executableURL: URL, timeout: TimeInterval = 30, verifySignature: Bool = true) throws {
        guard FileManager.default.isExecutableFile(atPath: executableURL.path) else {
            throw RoamSwitchClientError.serverBinaryNotFound
        }
        if verifySignature, !CodeSignatureVerifier.isSignedByRoamSwitch(at: executableURL) {
            throw RoamSwitchClientError.untrustedExecutable
        }
        self.executableURL = executableURL
        self.timeout = timeout
    }

    /// Runs RoamSwitch's full local Mac security audit (FileVault, SIP,
    /// Gatekeeper, auto-update, XProtect, firewall, Wi-Fi encryption, ARP
    /// spoofing, exposed ports) and returns a scored report.
    public func securityReport() async throws -> SecurityReport {
        try await call("get_security_report", arguments: [:], as: SecurityReport.self)
    }

    /// Lists every TCP port currently listening on this Mac and, for each
    /// one exposed beyond localhost, an audited risk level and recommendation.
    ///
    /// - Parameter includeLocalOnly: Include localhost-only ports in the
    ///   result (without the slower per-port audit). Defaults to false.
    public func exposedPorts(includeLocalOnly: Bool = false) async throws -> ExposedPorts {
        try await call("get_exposed_ports", arguments: ["includeLocalOnly": includeLocalOnly], as: ExposedPorts.self)
    }

    /// Reports whether RoamSwitch's optional Pro-tier auto-response guards
    /// are turned on in Settings, plus the currently active security level
    /// and trusted-network status.
    public func guardStatus() async throws -> GuardStatus {
        try await call("get_guard_status", arguments: [:], as: GuardStatus.self)
    }

    /// Analyzes an email link or web URL for phishing threats, Unicode
    /// homograph spoofing, brand subdomain deception, and high-risk TLDs
    /// without sending any data to external servers (Zero Telemetry).
    ///
    /// - Parameter url: The URL string to inspect.
    public func auditURLSafety(url: String) async throws -> LinkAuditReport {
        try await call("audit_url_safety", arguments: ["url": url], as: LinkAuditReport.self)
    }

    /// Audits macOS Unified Log security events (sudo/SSH/Gatekeeper/XProtect)
    /// over the given time window and returns the categorized findings plus
    /// any log-pattern anomalies (a pattern never seen before on this Mac, or
    /// one occurring far more often than usual this window). Every log
    /// message is scanned for API keys/tokens/private-key headers and masked
    /// before it ever leaves RoamSwitch.
    ///
    /// - Parameter hours: How far back to look, in hours. Defaults to 24.
    public func auditSecurityLogs(hours: Int = 24) async throws -> SecurityLogAudit {
        guard (1...Self.maxLogHours).contains(hours) else {
            throw RoamSwitchClientError.invalidArgument("hours must be in 1...\(Self.maxLogHours)")
        }
        return try await call("audit_security_logs", arguments: ["hours": hours], as: SecurityLogAudit.self)
    }

    /// Runs real, non-destructive network probes against this Mac's own
    /// listening ports (127.0.0.1 only) to verify whether a commonly-exposed
    /// service (Redis, MongoDB, Elasticsearch, etc.) actually responds
    /// unauthenticated, rather than only inferring risk from the port number.
    /// Off by default — returns `enabled: false` and no findings unless the
    /// user has opted in to this feature in RoamSwitch's Settings.
    public func activeVulnScan() async throws -> ActiveVulnScanResult {
        try await call("run_active_vuln_scan", arguments: [:], as: ActiveVulnScanResult.self)
    }

    /// Audits installed Homebrew formulae against RoamSwitch's local,
    /// network-free CVE map (real NVD CVE data for a hand-curated
    /// formula→CPE allowlist — never fabricated). Sends no network requests.
    public func packageCveScan() async throws -> PackageCveScanResult {
        try await call("run_package_cve_scan", arguments: [:], as: PackageCveScanResult.self)
    }

    /// Audits language-ecosystem lockfiles (npm/PyPI/crates.io/etc.) under
    /// the given folders against RoamSwitch's local CVE map. Sends no
    /// network requests.
    ///
    /// - Parameter watchedFolders: Absolute paths to scan for lockfiles.
    public func packageCveScanLanguages(watchedFolders: [String] = []) async throws -> PackageCveScanLanguagesResult {
        try await call("run_package_cve_scan_languages", arguments: ["watchedFolders": watchedFolders], as: PackageCveScanLanguagesResult.self)
    }

    /// Reports whether the Ransomware Canary Guard (Pro) is enabled, how
    /// many of its decoy bait files currently exist on disk, and up to the
    /// 50 most recent detected incidents. Sends no network requests — reads
    /// only local state, so this also works during a network Air-Gap.
    public func canaryStatus() async throws -> CanaryStatus {
        try await call("get_canary_status", arguments: [:], as: CanaryStatus.self)
    }

    /// Reports whether the Port Anomaly Guard (Pro) is enabled, whether it
    /// has captured its baseline yet, which ports are currently
    /// auto-isolated, and up to the 50 most recent detected incidents —
    /// previously-unseen executables that suddenly started listening on an
    /// externally-exposed port and were auto-blocked. Sends no network
    /// requests — reads only local state, so this also works during a
    /// network Air-Gap.
    public func portAnomalyIncidents() async throws -> PortAnomalyIncidentsSummary {
        try await call("get_port_anomaly_incidents", arguments: [:], as: PortAnomalyIncidentsSummary.self)
    }

    /// Reports whether the Runtime Threat Containment guard (Pro) is
    /// enabled, whether this Mac is currently network-isolated (Air-Gapped)
    /// because of it, and the single most recent malware incident that
    /// triggered containment — this guard fires when Apple's own XProtect
    /// malware engine actually convicts a file. Sends no network requests —
    /// reads only local state, so this also works during a network Air-Gap
    /// (indeed, it's one of the first things to check to understand why one
    /// is active).
    public func runtimeThreatStatus() async throws -> RuntimeThreatStatus {
        try await call("get_runtime_threat_status", arguments: [:], as: RuntimeThreatStatus.self)
    }

    /// Returns the notifications RoamSwitch has sent over the past 7 days,
    /// most recent first. Sends no network requests — reads only local
    /// state, so this also works during a network Air-Gap.
    public func notificationHistory() async throws -> [NotificationHistoryEntry] {
        try await call("get_notification_history", arguments: [:], as: NotificationHistoryWrapper.self).notifications
    }

    /// Scans a text snippet for exposed API keys (OpenAI, Anthropic, GitHub,
    /// AWS, HuggingFace, Google AI/Gemini, Slack, Stripe) and SSH/RSA private
    /// keys. Matches are masked before they leave RoamSwitch. Sends no
    /// network requests. Requires RoamSwitch 1.8.9+.
    public func auditSecrets(text: String) async throws -> SecretAuditResult {
        try await call("audit_secrets", arguments: ["text": text], as: SecretAuditResult.self)
    }

    /// Same as `auditSecrets(text:)`, for a file or (recursively) a
    /// directory at an absolute path. A missing path throws `.toolError`.
    /// Requires RoamSwitch 1.8.9+.
    public func auditSecrets(path: String) async throws -> SecretAuditResult {
        try await call("audit_secrets", arguments: ["path": path], as: SecretAuditResult.self)
    }

    /// The malware quarantine vault's contents (files are moved there by
    /// the Web/Mail download guard and ClamAV scans, never deleted). Reads
    /// only local state. Requires RoamSwitch 1.8.9+.
    public func quarantineStatus() async throws -> QuarantineStatus {
        try await call("get_quarantine_status", arguments: [:], as: QuarantineStatus.self)
    }

    /// Searches RoamSwitch's bundled knowledge base (features, alert
    /// messages, settings, troubleshooting). `query` may be in any language
    /// or be an alert-text substring; `topic` uses language-independent
    /// identifiers. Results come back in RoamSwitch's current UI language.
    /// Requires RoamSwitch 1.4.4+.
    public func appHelp(query: String? = nil, topic: AppHelpTopic? = nil) async throws -> AppHelpResult {
        var arguments: [String: Any] = [:]
        if let query { arguments["query"] = query }
        if let topic { arguments["topic"] = topic.rawValue }
        return try await call("get_app_help", arguments: arguments, as: AppHelpResult.self)
    }

    /// Unified, chronological containment timeline across ARP spoofing
    /// auto-containment, the Ransomware Canary Guard, Runtime Threat
    /// Containment and the Port Anomaly Guard (ARP containment is recorded
    /// only here). Reads only local state, so it also works during a network
    /// Air-Gap. Requires RoamSwitch 1.9.25+.
    ///
    /// - Parameter limit: Maximum events, newest first (1–200). Defaults to 50.
    public func incidentTimeline(limit: Int = 50) async throws -> IncidentTimeline {
        guard (1...Self.maxListLimit).contains(limit) else {
            throw RoamSwitchClientError.invalidArgument("limit must be in 1...\(Self.maxListLimit)")
        }
        return try await call("get_incident_timeline", arguments: ["limit": limit], as: IncidentTimeline.self)
    }

    /// Remembered Wi-Fi networks (SSID, gateway-device count, last seen —
    /// never MAC addresses) plus look-alike SSID pairs that never shared a
    /// gateway (Evil-Twin candidates). Reads only local state. Requires
    /// RoamSwitch 1.9.25+.
    ///
    /// - Parameter limit: Maximum networks, most recent first (1–200).
    ///   Defaults to 50. `lookalikePairs` is always complete.
    public func networkHistory(limit: Int = 50) async throws -> NetworkHistory {
        guard (1...Self.maxListLimit).contains(limit) else {
            throw RoamSwitchClientError.invalidArgument("limit must be in 1...\(Self.maxListLimit)")
        }
        return try await call("get_network_history", arguments: ["limit": limit], as: NetworkHistory.self)
    }

    /// Lists the bundled `roamswitch://docs/...` Markdown documents (MCP
    /// `resources/list`). Requires RoamSwitch 1.4.4+.
    public func docResources() async throws -> [DocResource] {
        try await request("resources/list", params: [:], as: DocResourceList.self).resources
    }

    /// Reads one bundled document by URI (MCP `resources/read`), e.g.
    /// `roamswitch://docs/features`. An unknown URI throws `.toolError`.
    /// Requires RoamSwitch 1.4.4+.
    public func readDocResource(uri: String) async throws -> DocResourceContent {
        let result = try await request("resources/read", params: ["uri": uri], as: DocResourceReadResult.self)
        guard let first = result.contents.first else {
            throw RoamSwitchClientError.invalidResponse(raw: "resources/read returned no contents for \(uri)")
        }
        return first
    }

    // MARK: - Private

    private static func timeoutClass(forTool name: String) -> TimeoutClass {
        switch name {
        case "get_security_report", "run_active_vuln_scan", "run_package_cve_scan",
             "run_package_cve_scan_languages", "audit_security_logs", "audit_secrets":
            return .heavy
        case "get_exposed_ports":
            return .normal
        default:
            return .light
        }
    }

    private func request<T: Decodable & Sendable>(
        _ method: String,
        params: [String: Any],
        as type: T.Type
    ) async throws -> T {
        let executableURL = self.executableURL
        let timeout = TimeoutClass.light.effective(self.timeout)
        let queue = self.transportQueue
        return try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    let transport = JSONRPCTransport(executableURL: executableURL, timeout: timeout)
                    let result = try transport.request(method: method, params: params)
                    continuation.resume(returning: try JSONRPCTransport.decodeResult(T.self, from: result))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private func call<T: Decodable & Sendable>(
        _ name: String,
        arguments: [String: Any],
        as type: T.Type
    ) async throws -> T {
        let executableURL = self.executableURL
        let timeout = Self.timeoutClass(forTool: name).effective(self.timeout)
        let queue = self.transportQueue
        return try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    let transport = JSONRPCTransport(executableURL: executableURL, timeout: timeout)
                    let result = try transport.callTool(name: name, arguments: arguments)
                    continuation.resume(returning: try JSONRPCTransport.decodeContent(T.self, from: result))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
