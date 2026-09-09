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

    /// - Parameters:
    ///   - appBundleID: RoamSwitch's bundle identifier. Only override this for
    ///     testing against a differently-identified build.
    ///   - timeout: Wall-clock ceiling for a single call. If the server hasn't
    ///     responded by then it is terminated and the call throws
    ///     `RoamSwitchClientError.timedOut`. Defaults to 30 seconds.
    /// - Throws: `RoamSwitchClientError.appNotInstalled` if no app with this
    ///   bundle ID is registered with Launch Services, or
    ///   `.serverBinaryNotFound` if the app is installed but predates 1.3.0.
    public init(appBundleID: String = "com.tetsuharu.RoamSwitch", timeout: TimeInterval = 30) throws {
        self.timeout = timeout
        if let envPath = ProcessInfo.processInfo.environment["ROAMSWITCH_SERVER_PATH"],
           FileManager.default.isExecutableFile(atPath: envPath) {
            self.executableURL = URL(fileURLWithPath: envPath)
            return
        }
        guard let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: appBundleID) else {
            throw RoamSwitchClientError.appNotInstalled
        }
        let binaryURL = appURL.appendingPathComponent("Contents/MacOS/RoamSwitchMCPServer")
        guard FileManager.default.isExecutableFile(atPath: binaryURL.path) else {
            throw RoamSwitchClientError.serverBinaryNotFound
        }
        self.executableURL = binaryURL
    }

    public init(executableURL: URL, timeout: TimeInterval = 30) throws {
        guard FileManager.default.isExecutableFile(atPath: executableURL.path) else {
            throw RoamSwitchClientError.serverBinaryNotFound
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
        try await call("audit_security_logs", arguments: ["hours": hours], as: SecurityLogAudit.self)
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

    // MARK: - Private

    private func call<T: Decodable & Sendable>(
        _ name: String,
        arguments: [String: Any],
        as type: T.Type
    ) async throws -> T {
        let executableURL = self.executableURL
        let timeout = self.timeout
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
