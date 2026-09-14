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
    public let timestamp: String
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
    /// `true` when the user never toggled this setting, so
    /// `enabledInSettings` is the guard's built-in default. `nil` from
    /// RoamSwitch builds older than 1.9.25.
    public let usingDefault: Bool?
}

/// Every property after `guards` except `caveats` is optional: RoamSwitch
/// builds older than 1.9.25 don't send them.
public struct GuardStatus: Codable, Equatable, Sendable {
    public let activeSecurityLevel: String
    public let activeSecurityLevelLabel: String
    public let isCurrentNetworkTrusted: Bool
    public let guards: [GuardEntry]
    public let caveats: [String]
    /// `"off"` | `"warn"` (pause and ask; blocked if unanswered) | `"block"`.
    public let linkGuardMode: String?
    /// `"wireguard"` | `"tailscale"`.
    public let vpnBackend: String?
    public let tailscaleExitNodeConfigured: Bool?
    /// `"quad9"` | `"cloudflareSecurity"` | `"adguard"` | `"cleanBrowsing"`.
    public let dnsThreatGuardProvider: String?
    /// `"awayOnly"` | `"always"`.
    public let dnsThreatGuardScope: String?
    public let isolatedDevPorts: [Int]?
    public let usbStorageAllowedVolumeCount: Int?
}


public struct LinkRiskFactor: Codable, Equatable, Sendable {
    public let title: String
    public let detail: String
    public let isSevere: Bool
    /// Language-independent identifier — `"invalidURL"`, `"plaintextHTTP"`,
    /// `"ipAddressHost"`, `"homograph"`, `"brandSubdomainSpoofing"`,
    /// `"highRiskTLD"`, `"nonStandardPort"`, `"phishingPathKeyword"`. Match on
    /// this, never on the localized `title`. `nil` before RoamSwitch 1.9.25.
    public let kind: String?
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

public struct ActiveVulnScanFinding: Codable, Equatable, Sendable {
    public let port: Int
    public let processName: String
    public let title: String
    public let description: String
    public let recommendation: String
}

/// One probe that did NOT produce a finding — either the target was
/// actually confirmed safe, or the probe itself couldn't complete
/// (connection refused, timeout). Kept separate from `findings` so a
/// caller can't mistake "checked, and it's fine" for "never actually got
/// to check" — both used to collapse into the same empty findings list
/// (see the 2026-09 discussion of `wait-for-it.sh` reporting success for a
/// port that never opened —
/// https://dev.to/raknaos/my-wait-for-it-wrapper-reported-success-for-a-port-that-never-opened-ga3).
public struct ScanCheckOutcome: Codable, Equatable, Sendable {
    public let port: Int
    public let processName: String
    public let check: String
}

public struct ActiveVulnScanResult: Codable, Equatable, Sendable {
    public let enabled: Bool
    public let scannedTargetCount: Int
    public let findings: [ActiveVulnScanFinding]
    /// Checks that ran to completion and found no issue. `nil` when talking
    /// to an app version that predates this field.
    public let confirmedSafe: [ScanCheckOutcome]?
    /// Checks that could not complete (unreachable/timeout) — never
    /// evidence of safety. `nil` when talking to an app version that
    /// predates this field.
    public let inconclusive: [ScanCheckOutcome]?
    public let message: String
}

public struct PackageCveFinding: Codable, Equatable, Sendable {
    public let cveId: String
    public let package: String
    public let installedVersion: String
    public let cvssScore: Double
    public let fixedVersion: String
    public let summary: String
    public let confidence: String
}

public struct PackageCveScanResult: Codable, Equatable, Sendable {
    public let mapInstalled: Bool
    public let mapVersion: String
    public let findings: [PackageCveFinding]
}

public struct PackageCveLanguageFinding: Codable, Equatable, Sendable {
    public let ecosystem: String
    public let cveId: String
    public let package: String
    public let installedVersion: String
    public let cvssScore: Double
    public let fixedVersion: String
    public let summary: String
}

public struct PackageCveScanLanguagesResult: Codable, Equatable, Sendable {
    public let scannedFolderCount: Int
    public let findings: [PackageCveLanguageFinding]
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

public struct CanaryIncident: Codable, Equatable, Sendable {
    public let timestamp: String
    public let fileName: String
    public let detectedAction: String
    public let suspectedProcess: String?
    public let affectedFilePaths: [String]
}

/// `recentIncidentsAvailable` is `true` whenever the Ransomware Canary Guard
/// has ever run — incident history is persisted to disk by the main app, so
/// a separate MCP server process (including this SDK's short-lived
/// subprocess calls) can read it.
public struct CanaryStatus: Codable, Equatable, Sendable {
    public let isEnabled: Bool
    public let monitoredFilesCount: Int
    public let expectedFilesCount: Int
    public let recentIncidentsAvailable: Bool
    public let recentIncidents: [CanaryIncident]
}

public struct PortAnomalyIncident: Codable, Equatable, Sendable {
    public let timestamp: String
    public let port: Int
    public let processName: String
    public let pid: Int
    public let executablePath: String?
}

public struct PortAnomalyIncidentsSummary: Codable, Equatable, Sendable {
    public let isEnabled: Bool
    public let baselineCaptured: Bool
    public let autoIsolatedPorts: [Int]
    public let incidents: [PortAnomalyIncident]
}

/// Mac equivalent of the Linux eBPF Runtime Guard's incident tool — fires
/// when Apple's own XProtect malware engine convicts a file (this app has no
/// EndpointSecurity entitlement for raw exec interception), then air-gaps
/// the network. Scoped to a single latest incident, not a history array.
public struct RuntimeThreatStatus: Codable, Equatable, Sendable {
    public let isEnabled: Bool
    public let isIsolated: Bool
    public let lastContainmentDate: String?
    public let lastIncident: SecurityLogEvent?
}

/// One notification RoamSwitch has sent (log-audit anomaly, ClickFix
/// detection, and the like) — entries older than 7 days are pruned before
/// this SDK ever sees them. Mirrors the Linux edition's
/// `roamswitchkit::NotificationHistoryEntry`.
public struct NotificationHistoryEntry: Codable, Equatable, Sendable {
    /// ISO 8601, so entries sort lexicographically in the same order as
    /// chronologically.
    public let timestamp: String
    public let title: String
    public let body: String
}

struct NotificationHistoryWrapper: Codable, Sendable {
    let notifications: [NotificationHistoryEntry]
}

// MARK: - audit_secrets

public struct SecretFinding: Codable, Equatable, Sendable {
    /// Detector identifier, e.g. an API-key provider or private-key type.
    public let type: String
    public let lineNumber: Int
    /// The matched value with most characters masked — the raw secret never
    /// leaves RoamSwitch.
    public let masked: String
    /// Shannon entropy of the match.
    public let entropy: Double
    public let filePath: String?
}

public struct SecretAuditResult: Codable, Equatable, Sendable {
    public let findings: [SecretFinding]
}

// MARK: - get_quarantine_status

public struct QuarantinedFile: Codable, Equatable, Sendable {
    public let originalPath: String
    public let quarantinedPath: String
    public let threatName: String
    /// ISO 8601
    public let quarantinedAt: String
    public let fileSize: Int64
}

public struct QuarantineStatus: Codable, Equatable, Sendable {
    public let quarantineDirectory: String
    public let files: [QuarantinedFile]
}

// MARK: - get_app_help

/// Topic filter for `appHelp(query:topic:)`. Raw values are the server's
/// wire identifiers and are the same in every UI language.
public enum AppHelpTopic: String, Codable, CaseIterable, Sendable {
    case all
    case feature
    case alertMessage = "alert_message"
    case setting
    case troubleshooting
}

public struct KnowledgeItem: Codable, Equatable, Sendable {
    public let id: String
    public let topic: String
    public let title: String
    public let summary: String
    public let details: String
    public let recommendation: String?
    public let tags: [String]
}

public struct AppHelpResult: Codable, Equatable, Sendable {
    public let query: String?
    public let topic: String?
    public let totalResults: Int
    public let items: [KnowledgeItem]
    /// Language the knowledge-base content was returned in (e.g. `"ja"`,
    /// `"en"`). `nil` from older RoamSwitch builds.
    public let language: String?
}

// MARK: - get_incident_timeline

public struct IncidentTimelineEvent: Codable, Equatable, Sendable {
    public let id: String
    /// ISO 8601
    public let timestamp: String
    /// `"arpSpoof"` | `"ransomwareCanary"` | `"runtimeThreat"` | `"portAnomaly"`
    public let source: String
    /// Localized display name for `source`.
    public let sourceLabel: String
    public let severity: String
    /// Recorded in the app's display language at detection time.
    public let summary: String
    public let processName: String?
    public let processID: Int32?
    /// MITRE ATT&CK technique ID — only set where confidently mappable.
    public let attackTechnique: String?
    /// `"air_gap"` | `"port_block"` | ...
    public let actionTaken: String
    public let actionTakenLabel: String
    /// `"open"` | `"released"` | `"autoTimeout"` | `"allowlisted"`
    public let status: String
    /// ISO 8601
    public let resolvedAt: String?
}

public struct IncidentTimeline: Codable, Equatable, Sendable {
    public let unresolvedCount: Int
    /// Newest first.
    public let events: [IncidentTimelineEvent]
    public let caveats: [String]
}

// MARK: - get_network_history

public struct KnownNetwork: Codable, Equatable, Sendable {
    public let ssid: String
    /// Distinct gateway devices seen answering for this SSID (the MAC
    /// addresses themselves are never returned).
    public let gatewayCount: Int
    /// ISO 8601
    public let lastSeen: String
}

/// Two remembered SSIDs with suspiciously similar names that never shared a
/// gateway device — a past Evil-Twin access point candidate.
public struct LookalikeNetworkPair: Codable, Equatable, Sendable {
    public let ssid: String
    public let similarTo: String
    public let editDistance: Int
}

public struct NetworkHistory: Codable, Equatable, Sendable {
    public let knownNetworkCount: Int
    /// Most recently seen first, capped by the requested limit.
    public let networks: [KnownNetwork]
    public let lookalikePairs: [LookalikeNetworkPair]
    public let caveats: [String]
}

// MARK: - resources/list, resources/read

public struct DocResource: Codable, Equatable, Sendable {
    public let uri: String
    public let name: String
    public let description: String
    public let mimeType: String
}

public struct DocResourceContent: Codable, Equatable, Sendable {
    public let uri: String
    public let mimeType: String
    public let text: String
}

struct DocResourceList: Codable, Sendable {
    let resources: [DocResource]
}

struct DocResourceReadResult: Codable, Sendable {
    let contents: [DocResourceContent]
}
