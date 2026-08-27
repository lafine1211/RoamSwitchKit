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

    /// - Parameter appBundleID: RoamSwitch's bundle identifier. Only override
    ///   this for testing against a differently-identified build.
    /// - Throws: `RoamSwitchClientError.appNotInstalled` if no app with this
    ///   bundle ID is registered with Launch Services, or
    ///   `.serverBinaryNotFound` if the app is installed but predates 1.3.0.
    public init(appBundleID: String = "com.tetsuharu.RoamSwitch") throws {
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

    public init(executableURL: URL) throws {
        guard FileManager.default.isExecutableFile(atPath: executableURL.path) else {
            throw RoamSwitchClientError.serverBinaryNotFound
        }
        self.executableURL = executableURL
    }

    /// Runs RoamSwitch's full local Mac security audit (FileVault, SIP,
    /// Gatekeeper, auto-update, XProtect, firewall, Wi-Fi encryption, ARP
    /// spoofing, exposed ports) and returns a scored report.
    public func securityReport() async throws -> SecurityReport {
        let result = try JSONRPCTransport(executableURL: executableURL)
            .callTool(name: "get_security_report", arguments: [:])
        return try JSONRPCTransport.decodeContent(SecurityReport.self, from: result)
    }

    /// Lists every TCP port currently listening on this Mac and, for each
    /// one exposed beyond localhost, an audited risk level and recommendation.
    ///
    /// - Parameter includeLocalOnly: Include localhost-only ports in the
    ///   result (without the slower per-port audit). Defaults to false.
    public func exposedPorts(includeLocalOnly: Bool = false) async throws -> ExposedPorts {
        let result = try JSONRPCTransport(executableURL: executableURL)
            .callTool(name: "get_exposed_ports", arguments: ["includeLocalOnly": includeLocalOnly])
        return try JSONRPCTransport.decodeContent(ExposedPorts.self, from: result)
    }

    /// Reports whether RoamSwitch's optional Pro-tier auto-response guards
    /// are turned on in Settings, plus the currently active security level
    /// and trusted-network status.
    public func guardStatus() async throws -> GuardStatus {
        let result = try JSONRPCTransport(executableURL: executableURL)
            .callTool(name: "get_guard_status", arguments: [:])
        return try JSONRPCTransport.decodeContent(GuardStatus.self, from: result)
    }

    /// Analyzes an email link or web URL for phishing threats, Unicode
    /// homograph spoofing, brand subdomain deception, and high-risk TLDs
    /// without sending any data to external servers (Zero Telemetry).
    ///
    /// - Parameter url: The URL string to inspect.
    public func auditURLSafety(url: String) async throws -> LinkAuditReport {
        let result = try JSONRPCTransport(executableURL: executableURL)
            .callTool(name: "audit_url_safety", arguments: ["url": url])
        return try JSONRPCTransport.decodeContent(LinkAuditReport.self, from: result)
    }
}
