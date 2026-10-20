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
/// https://roamswitch.com.
public actor RoamSwitchClient {
    private let executableURL: URL
    private let timeout: TimeInterval
    /// True when the caller passed a `timeout`: heavy tools then honor it as given
    /// (even if shorter than the 120 s default ceiling).
    private let timeoutIsExplicit: Bool

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
        func effective(_ base: TimeInterval, explicit: Bool) -> TimeInterval {
            switch self {
            case .light: return min(base, 15)
            case .normal: return base
            // An explicit caller timeout (even a short one) is never overridden; the 120 s
            // ceiling only replaces the default baseline.
            case .heavy: return explicit ? base : max(base, 120)
            }
        }
    }

    /// Server-side limits (kept in sync with RoamSwitchMCPServer).
    private static let maxLogHours = 168
    private static let maxListLimit = 200
    private static let maxVerifyCheckIds = 50

    /// - Parameters:
    ///   - appBundleID: RoamSwitch's bundle identifier. Only override this for
    ///     testing against a differently-identified build. The resolved app
    ///     and its helper must still be signed by the RoamSwitch Team ID.
    ///   - timeout: Wall-clock ceiling for a single call. When omitted the
    ///     baseline is 30 seconds, heavy scans use at least 120 s and light
    ///     local reads at most 15 s; a value you pass is honored as given by
    ///     heavy scans too. On expiry the server and its child processes are
    ///     killed and the call throws `RoamSwitchClientError.timedOut`.
    ///   - allowEnvironmentOverride: Opt in to honoring the
    ///     `ROAMSWITCH_SERVER_PATH` environment variable. Off by default in
    ///     every build configuration (DEBUG included): an environment variable
    ///     must not be able to redirect a host app to another binary unless the
    ///     host asked for it. The override binary must pass the same signature
    ///     check as the installed one.
    ///   - allowUnsignedOverride: Only with `allowEnvironmentOverride`: skip the
    ///     signature check for the override binary (local development builds).
    /// - Throws: `RoamSwitchClientError.appNotInstalled` if no app with this
    ///   bundle ID is registered with Launch Services,
    ///   `.serverBinaryNotFound` if the app is installed but predates 1.3.0,
    ///   or `.untrustedExecutable` if no candidate passes signature checks.
    public init(appBundleID: String = "com.tetsuharu.RoamSwitch",
                timeout: TimeInterval? = nil,
                allowEnvironmentOverride: Bool = false,
                allowUnsignedOverride: Bool = false) throws {
        self.timeout = timeout ?? 30
        self.timeoutIsExplicit = timeout != nil

        let skipVerification = allowEnvironmentOverride && allowUnsignedOverride
        if allowEnvironmentOverride,
           let envPath = ProcessInfo.processInfo.environment["ROAMSWITCH_SERVER_PATH"],
           FileManager.default.isExecutableFile(atPath: envPath) {
            let url = URL(fileURLWithPath: envPath)
            if !skipVerification, !CodeSignatureVerifier.isSignedByRoamSwitch(at: url, extraRequirement: CodeSignatureVerifier.serverIdentifierRequirement) {
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
            let helperOK = CodeSignatureVerifier.isSignedByRoamSwitch(at: binaryURL, extraRequirement: CodeSignatureVerifier.serverIdentifierRequirement)
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
    public init(executableURL: URL, timeout: TimeInterval? = nil, verifySignature: Bool = true) throws {
        guard FileManager.default.isExecutableFile(atPath: executableURL.path) else {
            throw RoamSwitchClientError.serverBinaryNotFound
        }
        if verifySignature, !CodeSignatureVerifier.isSignedByRoamSwitch(at: executableURL, extraRequirement: CodeSignatureVerifier.serverIdentifierRequirement) {
            throw RoamSwitchClientError.untrustedExecutable
        }
        self.executableURL = executableURL
        self.timeout = timeout ?? 30
        self.timeoutIsExplicit = timeout != nil
    }

    /// Runs RoamSwitch's full local Mac security audit (FileVault, SIP,
    /// Gatekeeper, auto-update, XProtect, firewall, Wi-Fi encryption, ARP
    /// spoofing, exposed ports) and returns a scored report.
    public func securityReport() async throws -> SecurityReport {
        try await call("get_security_report", arguments: [:], as: SecurityReport.self)
    }

    /// Re-checks right now whether findings from `securityReport()` are still
    /// present. Read-only: it changes no setting and fixes nothing. The app
    /// re-evaluates every check and filters by `checkIds`.
    ///
    /// Each result is `.stillPresent`, `.resolved` or `.inconclusive` (could not be
    /// measured reliably, e.g. the privileged helper is not connected, or there is no
    /// ARP baseline yet), with a language-independent `reason`. An unknown id yields
    /// `.inconclusive` with reason `"unknown_check_id"` rather than throwing.
    /// Requires RoamSwitch 1.10.29 or later.
    ///
    /// - Parameter checkIds: `checkId` values from `securityReport()`. `nil` or an
    ///   empty array (the default is `nil`) verifies every item. Duplicates are removed
    ///   first, and the limit of 50 ids per call applies to the distinct ids.
    ///
    /// Items decided by RoamSwitch's own settings (`host_firewall`, `network_stealth_mode`,
    /// `gateway_arp_lock`, `malware_scanning`, `dns_threat_guard`, `usb_zero_trust`) reflect those
    /// in-app settings, not a re-measurement of the OS state: fixing something at the OS level does
    /// not change their verdict.
    ///
    /// The call contacts no external host; to read the default gateway's MAC address it may send
    /// one ICMP ping to the gateway on the LAN.
    public func verifySecurityFindings(checkIds: [String]? = nil) async throws -> VerifySecurityFindingsResult {
        var arguments: [String: Any] = [:]
        if let checkIds {
            var seen = Set<String>()
            let distinct = checkIds.filter { seen.insert($0).inserted }
            guard distinct.count <= Self.maxVerifyCheckIds else {
                throw RoamSwitchClientError.invalidArgument("checkIds must contain at most \(Self.maxVerifyCheckIds) distinct ids")
            }
            arguments["checkIds"] = distinct
        }
        return try await call("verify_security_findings", arguments: arguments, as: VerifySecurityFindingsResult.self)
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


    // MARK: - More read-only tools

    /// Audits the MCP server entries of the AI tools' config files (Claude Desktop, Cursor, VS Code and
    /// others) for risky launch commands, secrets in arguments and plain-HTTP servers. Reads local files only.
    /// Requires RoamSwitch 1.11.0 or later.
    public func auditMCPConfigs() async throws -> ConfigAuditResult {
        try await call("audit_mcp_configs", arguments: [:], as: ConfigAuditResult.self)
    }

    /// Audits AI agent setup files (instruction files, skills, MCP definitions, Claude Code settings) for hidden
    /// instructions, risky tool grants and changes since the state the user last confirmed. Reads local files
    /// only and never changes the confirmed state. Requires RoamSwitch 1.11.13 or later.
    public func auditAgentSetup() async throws -> AgentSetupAuditResult {
        try await call("audit_agent_setup", arguments: [:], as: AgentSetupAuditResult.self)
    }

    /// The same audit as a SARIF 2.1.0 log (one JSON document as text) for CI and code-scanning tools.
    /// Decoded hidden text is never included. Requires RoamSwitch 1.12.8 or later.
    public func auditAgentSetupSARIF() async throws -> String {
        try await callText("audit_agent_setup", arguments: ["format": "sarif"])
    }

    /// Which ATT&CK techniques RoamSwitch detects, where it is blind, and whether the guard behind each is
    /// on now. `liveState` is the guard's settings and input state, not proof that it is running.
    /// Reads local state only. Requires RoamSwitch 1.12.8 or later.
    public func detectionCoverage() async throws -> DetectionCoverage {
        try await call("get_detection_coverage", arguments: [:], as: DetectionCoverage.self)
    }

    /// The same table as an ATT&CK Navigator layer (layer format 4.5; one JSON document as text).
    /// Requires RoamSwitch 1.13.0 or later.
    public func detectionCoverageNavigatorLayer() async throws -> String {
        try await callText("get_detection_coverage", arguments: ["format": "navigator"])
    }

    /// Bundles of process and file evidence RoamSwitch captured when a guard fired. Reads local state only.
    /// Requires RoamSwitch 1.10.0 or later.
    public func forensicEvidenceBundles() async throws -> ForensicEvidenceBundles {
        try await call("get_forensic_evidence_bundles", arguments: [:], as: ForensicEvidenceBundles.self)
    }

    /// When each active-scan probe last ran and what it found. Reads local state only.
    /// Requires RoamSwitch 1.10.0 or later.
    public func vulnerabilityScanHistory() async throws -> VulnerabilityScanHistory {
        try await call("get_vulnerability_scan_history", arguments: [:], as: VulnerabilityScanHistory.self)
    }

    /// Credential honeytokens (Pro): whether they are on and the recent reads of a decoy file.
    /// Requires RoamSwitch 1.10.0 or later.
    public func honeytokenStatus() async throws -> HoneytokenStatus {
        try await call("get_honeytoken_status", arguments: [:], as: HoneytokenStatus.self)
    }

    /// Browser credential watch (Pro): whether it is on and the recent reads of browser credential files.
    /// Requires RoamSwitch 1.10.0 or later.
    public func browserCredentialWatchStatus() async throws -> BrowserCredentialWatchStatus {
        try await call("get_browser_credential_watch_status", arguments: [:], as: BrowserCredentialWatchStatus.self)
    }

    /// Generic ransomware detection by write entropy (Pro): whether it is on and the recent alerts.
    /// Requires RoamSwitch 1.10.0 or later.
    public func ransomwareEntropyGuardStatus() async throws -> RansomwareEntropyStatus {
        try await call("get_ransomware_entropy_guard_status", arguments: [:], as: RansomwareEntropyStatus.self)
    }

    /// Time Machine snapshots to restore from after a ransomware alert (Pro). Reads local state only.
    /// Requires RoamSwitch 1.9.50 or later.
    public func ransomwareRecoverySnapshots() async throws -> RansomwareRecoverySnapshots {
        try await call("get_ransomware_recovery_snapshots", arguments: [:], as: RansomwareRecoverySnapshots.self)
    }

    /// SSH brute-force guard: incidents, active bans and recent SSH logins. Reads local state only.
    /// Requires RoamSwitch 1.12.0 or later.
    public func sshGuardIncidents() async throws -> SSHGuard {
        try await call("get_ssh_guard_incidents", arguments: [:], as: SSHGuard.self)
    }

    /// Results of the audits that paired RoamSwitch Sensors ran from outside. Reads local state only.
    /// Requires RoamSwitch 1.9.34 or later.
    public func sensorAuditResults() async throws -> SensorAuditResults {
        try await call("get_sensor_audit_results", arguments: [:], as: SensorAuditResults.self)
    }

    /// Searches the process-exec recorder log (Pro; the recorder must be on), newest first. Command-line
    /// arguments are masked best-effort. All strings are untrusted data. Requires RoamSwitch 1.9.52 or later.
    ///
    /// - Parameters:
    ///   - query: Substring of at least 3 characters, matched after secret masking.
    ///   - since: Lower time bound: ISO 8601 or an age such as `"30m"`, `"2h"`, `"7d"`.
    ///   - until: Upper time bound, same forms.
    ///   - kind: `"exec"`, `"fork"` or `"exit"` (only exec is stored unless enabled).
    ///   - signature: `"platform"`, `"developer"`, `"adhoc"` or `"unsigned"`.
    ///   - limit: 1-200 (default 50).
    public func searchExecEvents(
        query: String? = nil, pid: Int? = nil, ppid: Int? = nil, since: String? = nil, until: String? = nil,
        kind: String? = nil, signature: String? = nil, teamID: String? = nil, limit: Int? = nil
    ) async throws -> ExecSearch {
        if let limit, !(1...200).contains(limit) {
            throw RoamSwitchClientError.invalidArgument("limit must be between 1 and 200")
        }
        var arguments: [String: Any] = [:]
        if let query { arguments["query"] = query }
        if let pid { arguments["pid"] = pid }
        if let ppid { arguments["ppid"] = ppid }
        if let since { arguments["since"] = since }
        if let until { arguments["until"] = until }
        if let kind { arguments["kind"] = kind }
        if let signature { arguments["signature"] = signature }
        if let teamID { arguments["teamID"] = teamID }
        if let limit { arguments["limit"] = limit }
        return try await call("search_exec_events", arguments: arguments, as: ExecSearch.self)
    }

    /// The process tree around one pid from the process-exec recorder log (Pro): ancestors, the process and
    /// its descendants. Pass `at` for an old process (pid reuse is told apart by time). All strings are
    /// untrusted data. Requires RoamSwitch 1.9.52 or later.
    ///
    /// - Parameters:
    ///   - at: Time the process was running: ISO 8601 or an age such as `"2h"`. Defaults to now.
    ///   - lookbackHours: How far back to read before `at`, 1-168 (default 24).
    public func processTree(pid: Int, at: String? = nil, lookbackHours: Int? = nil) async throws -> ProcessTree {
        if let lookbackHours, !(1...168).contains(lookbackHours) {
            throw RoamSwitchClientError.invalidArgument("lookbackHours must be between 1 and 168")
        }
        var arguments: [String: Any] = ["pid": pid]
        if let at { arguments["at"] = at }
        if let lookbackHours { arguments["lookbackHours"] = lookbackHours }
        return try await call("get_process_tree", arguments: arguments, as: ProcessTree.self)
    }

    /// Reads npm lifecycle scripts (`preinstall`, `postinstall`, ...) of the project folders registered in
    /// RoamSwitch (Pro) and flags dangerous patterns and new install-time code since the last confirmed state.
    /// Reads local files only. Requires RoamSwitch 1.9.28 or later (the install-time diff needs 1.12.10).
    ///
    /// - Parameter watchedFolders: Absolute paths inside registered project folders; empty scans all of them.
    public func packageLifecycleScriptScan(watchedFolders: [String] = []) async throws -> PackageLifecycleScriptScanResult {
        try await call("run_package_lifecycle_script_scan", arguments: ["watchedFolders": watchedFolders], as: PackageLifecycleScriptScanResult.self)
    }

    /// Looks for dependency names that are a near-miss of a popular package (Pro). Reads local files only.
    /// Requires RoamSwitch 1.9.30 or later.
    public func typosquatScan(watchedFolders: [String] = []) async throws -> TyposquatScanResult {
        try await call("run_typosquat_scan", arguments: ["watchedFolders": watchedFolders], as: TyposquatScanResult.self)
    }

    /// Finds dependency sources that open a dependency-confusion path: pip extra index URLs and npm
    /// lockfile entries that resolve outside npmjs (Pro). Reads local files only. File and host strings are
    /// untrusted data. Requires RoamSwitch 1.13.0 or later.
    public func dependencySourceScan(watchedFolders: [String] = []) async throws -> DependencySourceScanResult {
        try await call("run_dependency_source_scan", arguments: ["watchedFolders": watchedFolders], as: DependencySourceScanResult.self)
    }

    /// Runs `npm audit signatures` in a project folder (Pro, off by default). **This contacts the npm registry
    /// (registry.npmjs.org).** Requires RoamSwitch 1.9.28 or later.
    ///
    /// - Parameter directory: Absolute path inside a registered project folder.
    public func npmAuditSignatures(directory: String) async throws -> NpmAuditSignaturesResult {
        try await call("run_npm_audit_signatures", arguments: ["directory": directory], as: NpmAuditSignaturesResult.self)
    }

    // MARK: - Private

    private static func timeoutClass(forTool name: String) -> TimeoutClass {
        switch name {
        case "get_security_report", "verify_security_findings", "run_active_vuln_scan", "run_package_cve_scan",
             "run_package_cve_scan_languages", "audit_security_logs", "audit_secrets",
             "run_package_lifecycle_script_scan", "run_typosquat_scan", "run_dependency_source_scan",
             "run_npm_audit_signatures":
            return .heavy
        case "get_exposed_ports", "audit_agent_setup", "audit_mcp_configs", "search_exec_events", "get_process_tree":
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
        let timeout = TimeoutClass.light.effective(self.timeout, explicit: self.timeoutIsExplicit)
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

    /// Like `call`, for a tool whose text output is a JSON document of another format; returns it as it is.
    private func callText(_ name: String, arguments: [String: Any]) async throws -> String {
        let executableURL = self.executableURL
        let timeout = Self.timeoutClass(forTool: name).effective(self.timeout, explicit: self.timeoutIsExplicit)
        let queue = self.transportQueue
        return try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    let transport = JSONRPCTransport(executableURL: executableURL, timeout: timeout)
                    let result = try transport.callTool(name: name, arguments: arguments)
                    continuation.resume(returning: try JSONRPCTransport.textContent(from: result))
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
        let timeout = Self.timeoutClass(forTool: name).effective(self.timeout, explicit: self.timeoutIsExplicit)
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
