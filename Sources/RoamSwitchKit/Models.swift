import Foundation

// Mirrors the JSON shape returned by RoamSwitchMCPServer's three read-only
// tools (see RoamSwitch/MCPResponseFormatting.swift in the main app repo).
// That JSON-RPC response is the actual contract between this package and
// the app; these types are an intentional duplicate, not a shared import,
// since RoamSwitchKit is a separate public repo and can't depend on the
// private RoamSwitch app target.

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

public struct SecurityReport: Codable, Equatable, Sendable {
    public let score: Int
    public let grade: String
    public let totalChecks: Int
    public let passedChecks: Int
    public let items: [SecurityAuditItem]
    public let caveats: [String]
}

public struct PortFinding: Codable, Equatable, Sendable {
    public let title: String
    public let riskLevel: String
    public let description: String
    public let recommendation: String
}

public struct ExposedPort: Codable, Equatable, Sendable {
    public let processName: String
    public let pid: Int
    public let port: Int
    public let isGloballyExposed: Bool
    public let executablePath: String?
    public let auditPerformed: Bool
    public let overallRisk: String?
    public let findings: [PortFinding]
    public let httpHeaders: [String: String]?
}

public struct ExposedPorts: Codable, Equatable, Sendable {
    public let isFirewallShielded: Bool
    public let ports: [ExposedPort]
}

public struct GuardEntry: Codable, Equatable, Sendable {
    public let key: String
    public let enabledInSettings: Bool
}

public struct GuardStatus: Codable, Equatable, Sendable {
    public let activeSecurityLevel: String
    public let activeSecurityLevelLabel: String
    public let isCurrentNetworkTrusted: Bool
    public let guards: [GuardEntry]
    public let caveats: [String]
}


public struct LinkRiskFactor: Codable, Equatable, Sendable {
    public let title: String
    public let detail: String
    public let isSevere: Bool
}

public struct LinkAuditReport: Codable, Equatable, Sendable {
    public let originalURL: String
    public let finalURL: String
    public let redirectChain: [String]
    public let domain: String
    public let score: Int
    public let riskLevel: String
    public let isHTTPS: Bool
    public let riskFactors: [LinkRiskFactor]
}

public struct SecurityLogEvent: Codable, Equatable, Sendable {
    public let timestamp: String
    public let process: String
    public let category: String
    public let severity: String
    public let message: String
}

/// A log pattern flagged as anomalous — either never seen before on this
/// Mac, or a statistical frequency outlier within the scanned time window.
public struct TemplateAnomaly: Codable, Equatable, Sendable {
    public let template: String
    public let example: String
    public let count: Int
    public let zScore: Double
    public let isNew: Bool
}

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
