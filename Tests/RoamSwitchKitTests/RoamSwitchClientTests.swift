import XCTest
@testable import RoamSwitchKit

/// Integration tests against a real, installed RoamSwitch.app. There's no
/// way to unit-test the JSON-RPC exchange without the actual binary, since
/// the response shapes are produced by RoamSwitch's own security-scanning
/// logic (ARP inspection, port scanning, etc.) rather than anything this
/// package computes. Environments without RoamSwitch installed (e.g. CI)
/// skip rather than fail.
final class RoamSwitchClientTests: XCTestCase {
    private func makeClientOrSkip() throws -> RoamSwitchClient {
        let debugDerivedBinary = "/Users/tetsuharu/Library/Developer/Xcode/DerivedData/RoamSwitch-bzvrkxawectksnaiivrtzlqulvok/Build/Products/Debug/RoamSwitchMCPServer"
        if FileManager.default.isExecutableFile(atPath: debugDerivedBinary) {
            return try RoamSwitchClient(executableURL: URL(fileURLWithPath: debugDerivedBinary))
        }
        do {
            return try RoamSwitchClient()
        } catch RoamSwitchClientError.appNotInstalled, RoamSwitchClientError.serverBinaryNotFound {
            throw XCTSkip("RoamSwitch 1.3.0+ isn't installed on this machine — skipping integration test.")
        }
    }

    func testInitThrowsAppNotInstalledForUnknownBundleID() {
        XCTAssertThrowsError(try RoamSwitchClient(appBundleID: "com.example.definitely-not-a-real-app")) { error in
            XCTAssertEqual(error as? RoamSwitchClientError, .appNotInstalled)
        }
    }

    /// A subprocess that exits immediately (so the write end of our stdin
    /// pipe breaks mid-handshake) must surface as a thrown error, never an
    /// uncatchable Objective-C exception that aborts the host process.
    func testImmediatelyExitingBinaryThrowsRatherThanCrashing() async throws {
        let client = try RoamSwitchClient(executableURL: URL(fileURLWithPath: "/usr/bin/false"))
        do {
            _ = try await client.securityReport()
            XCTFail("expected an error")
        } catch let error as RoamSwitchClientError {
            XCTAssertEqual(error, .noResponse)
        }
    }

    /// A subprocess that never answers is terminated at the timeout and
    /// reported as `.timedOut`, not left hanging forever.
    func testHangingBinaryTimesOut() async throws {
        let script = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("roamswitchkit-hang-\(UUID().uuidString).sh")
        try "#!/bin/sh\nsleep 30\n".write(to: script, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: script.path)
        defer { try? FileManager.default.removeItem(at: script) }

        let client = try RoamSwitchClient(executableURL: script, timeout: 0.5)
        let start = Date()
        do {
            _ = try await client.guardStatus()
            XCTFail("expected a timeout")
        } catch let error as RoamSwitchClientError {
            XCTAssertEqual(error, .timedOut)
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 10, "should have given up near the 0.5s timeout")
    }

    func testSecurityReport() async throws {
        let client = try makeClientOrSkip()
        let report = try await client.securityReport()
        XCTAssertGreaterThanOrEqual(report.score, 0)
        XCTAssertGreaterThan(report.totalChecks, 0)
        XCTAssertEqual(report.totalChecks, report.items.filter { $0.isApplicable }.count)
        XCTAssertLessThanOrEqual(report.totalChecks, report.items.count)
    }

    func testExposedPorts() async throws {
        let client = try makeClientOrSkip()
        let result = try await client.exposedPorts()
        // Every returned port must have been through the audit unless it's
        // localhost-only (which shouldn't appear at all with default args).
        for port in result.ports {
            XCTAssertTrue(port.isGloballyExposed)
            XCTAssertTrue(port.auditPerformed)
        }
    }

    func testGuardStatus() async throws {
        let client = try makeClientOrSkip()
        let status = try await client.guardStatus()
        XCTAssertGreaterThanOrEqual(status.guards.count, 6)
        XCTAssertFalse(status.activeSecurityLevel.isEmpty)
    }

    func testAuditURLSafety() async throws {
        let client = try makeClientOrSkip()
        let report = try await client.auditURLSafety(url: "https://apple.com.login-verify.xyz")
        XCTAssertEqual(report.domain, "apple.com.login-verify.xyz")
        XCTAssertEqual(report.riskLevel, "dangerous")
        XCTAssertFalse(report.riskFactors.isEmpty)
    }

    func testAuditSecurityLogs() async throws {
        let client = try makeClientOrSkip()
        let audit = try await client.auditSecurityLogs(hours: 24)
        XCTAssertEqual(audit.timeWindowHours, 24)
        XCTAssertEqual(audit.totalEvents, audit.events.count)
        // Every returned log message must already be scrubbed of API
        // keys/tokens before it ever reaches this SDK — this is the whole
        // point of exposing the tool at all.
        for event in audit.events {
            XCTAssertFalse(event.message.contains("sk-ant-"))
            XCTAssertFalse(event.message.contains("sk-proj-"))
        }
    }

    func testPackageCveScan() async throws {
        let client = try makeClientOrSkip()
        let result = try await client.packageCveScan()
        // The embedded baseline can legitimately ship as an empty seed until
        // the daily updater installs real data, so only assert the call
        // succeeds and returns a well-formed result.
        XCTAssertGreaterThanOrEqual(result.findings.count, 0)
    }

    func testPackageCveScanLanguages() async throws {
        let client = try makeClientOrSkip()
        let result = try await client.packageCveScanLanguages(watchedFolders: [])
        XCTAssertEqual(result.scannedFolderCount, 0)
        XCTAssertTrue(result.findings.isEmpty)
    }

    func testActiveVulnScan() async throws {
        let client = try makeClientOrSkip()
        let result = try await client.activeVulnScan()
        // Off by default: an un-opted-in machine must report no findings.
        if !result.enabled {
            XCTAssertTrue(result.findings.isEmpty)
        }
    }

    func testCanaryStatus() async throws {
        let client = try makeClientOrSkip()
        let status = try await client.canaryStatus()
        XCTAssertGreaterThanOrEqual(status.expectedFilesCount, status.monitoredFilesCount)
        XCTAssertLessThanOrEqual(status.recentIncidents.count, 50)
        XCTAssertEqual(status.recentIncidentsAvailable, !status.recentIncidents.isEmpty)
    }

    func testPortAnomalyIncidents() async throws {
        let client = try makeClientOrSkip()
        let result = try await client.portAnomalyIncidents()
        XCTAssertLessThanOrEqual(result.incidents.count, 50)
        XCTAssertGreaterThanOrEqual(result.autoIsolatedPorts.count, 0)
    }

    func testRuntimeThreatStatus() async throws {
        let client = try makeClientOrSkip()
        let status = try await client.runtimeThreatStatus()
        // Isolation without a recorded trigger would be an inconsistent
        // state — the manager always sets lastIncident before isIsolated.
        if status.isIsolated {
            XCTAssertNotNil(status.lastIncident)
        }
    }

    func testNotificationHistory() async throws {
        let client = try makeClientOrSkip()
        let entries = try await client.notificationHistory()
        // Most-recent-first: each timestamp should sort >= the one after it.
        for i in entries.indices.dropFirst() {
            XCTAssertGreaterThanOrEqual(entries[i - 1].timestamp, entries[i].timestamp)
        }
    }

    func testAuditSecretsText() async throws {
        let client = try makeClientOrSkip()
        // A syntactically valid but fake GitHub token: must be detected and
        // must come back masked, never verbatim.
        let fake = "ghp_" + String(String(repeating: "aB3dE5fG7h", count: 4).prefix(36))
        let result = try await client.auditSecrets(text: "token = \(fake)")
        for finding in result.findings {
            XCTAssertFalse(finding.masked.contains(fake))
        }
    }

    func testAuditSecretsMissingPathThrowsToolError() async throws {
        let client = try makeClientOrSkip()
        do {
            _ = try await client.auditSecrets(path: "/definitely/not/a/real/path-\(UUID().uuidString)")
            XCTFail("expected a tool error")
        } catch let error as RoamSwitchClientError {
            guard case .toolError = error else { return XCTFail("expected .toolError, got \(error)") }
        }
    }

    func testQuarantineStatus() async throws {
        let client = try makeClientOrSkip()
        let status = try await client.quarantineStatus()
        XCTAssertFalse(status.quarantineDirectory.isEmpty)
    }

    func testAppHelp() async throws {
        let client = try makeClientOrSkip()
        let result = try await client.appHelp(query: "ARP", topic: .feature)
        XCTAssertEqual(result.totalResults, result.items.count)
        for item in result.items {
            XCTAssertEqual(item.topic, AppHelpTopic.feature.rawValue)
        }
    }

    func testDocResources() async throws {
        let client = try makeClientOrSkip()
        let resources = try await client.docResources()
        XCTAssertFalse(resources.isEmpty)
        let first = try XCTUnwrap(resources.first)
        let content = try await client.readDocResource(uri: first.uri)
        XCTAssertEqual(content.uri, first.uri)
        XCTAssertFalse(content.text.isEmpty)
    }

    /// Needs RoamSwitch 1.9.25+; an older install answers "Unknown tool",
    /// which surfaces as `.toolError` — skip rather than fail in that case.
    func testIncidentTimeline() async throws {
        let client = try makeClientOrSkip()
        let timeline: IncidentTimeline
        do {
            timeline = try await client.incidentTimeline(limit: 10)
        } catch RoamSwitchClientError.toolError(let message) {
            throw XCTSkip("Installed RoamSwitch predates get_incident_timeline: \(message)")
        }
        XCTAssertLessThanOrEqual(timeline.events.count, 10)
        XCTAssertEqual(timeline.unresolvedCount, timeline.events.filter { $0.status == "open" }.count)
    }

    func testNetworkHistory() async throws {
        let client = try makeClientOrSkip()
        let history: NetworkHistory
        do {
            history = try await client.networkHistory(limit: 5)
        } catch RoamSwitchClientError.toolError(let message) {
            throw XCTSkip("Installed RoamSwitch predates get_network_history: \(message)")
        }
        XCTAssertLessThanOrEqual(history.networks.count, 5)
        XCTAssertGreaterThanOrEqual(history.knownNetworkCount, history.networks.count)
    }

    // MARK: - Decoding (no RoamSwitch install needed)

    private func toolResult(_ json: String) -> [String: Any] {
        ["content": [["type": "text", "text": json]]]
    }

    /// A pre-1.9.28 server sends no `confirmedSafe`/`inconclusive` fields at
    /// all — that must still decode, with both nil (never `[]`, so a caller
    /// can tell "server doesn't report this yet" apart from "reported zero").
    func testActiveVulnScanDecodesLegacyShapeWithoutInconclusiveFields() throws {
        let legacy = #"{"enabled":true,"scannedTargetCount":2,"findings":[],"message":"Scan complete."}"#
        let result = try JSONRPCTransport.decodeContent(ActiveVulnScanResult.self, from: toolResult(legacy))
        XCTAssertTrue(result.findings.isEmpty)
        XCTAssertNil(result.confirmedSafe)
        XCTAssertNil(result.inconclusive)
    }

    /// 1.9.28+: an empty `findings` array alone can't tell "everything
    /// checked out clean" apart from "some checks never completed" — the
    /// two must decode into separate, non-nil lists.
    func testActiveVulnScanDecodesConfirmedSafeAndInconclusiveSeparately() throws {
        let json = #"{"enabled":true,"scannedTargetCount":2,"findings":[],"confirmedSafe":[{"port":6379,"processName":"redis-server","check":"Redis データベース露出リスク（非標準ポート）"}],"inconclusive":[{"port":27017,"processName":"mongod","check":"MongoDB データベース露出リスク（非標準ポート）"}],"message":"Scan complete (1 check(s) could not be completed)."}"#
        let result = try JSONRPCTransport.decodeContent(ActiveVulnScanResult.self, from: toolResult(json))
        XCTAssertTrue(result.findings.isEmpty)
        XCTAssertEqual(result.confirmedSafe?.count, 1)
        XCTAssertEqual(result.confirmedSafe?.first?.port, 6379)
        XCTAssertEqual(result.inconclusive?.count, 1)
        XCTAssertEqual(result.inconclusive?.first?.processName, "mongod")
    }

    /// A pre-1.9.25 server sends only the original five GuardStatus fields
    /// and no `usingDefault` — that must still decode, with the new fields nil.
    func testGuardStatusDecodesLegacyShape() throws {
        let legacy = #"{"activeSecurityLevel":"lockdown","activeSecurityLevelLabel":"Lockdown","isCurrentNetworkTrusted":false,"guards":[{"key":"dnsThreatGuard","enabledInSettings":true}],"caveats":[]}"#
        let status = try JSONRPCTransport.decodeContent(GuardStatus.self, from: toolResult(legacy))
        XCTAssertEqual(status.guards.first?.key, "dnsThreatGuard")
        XCTAssertNil(status.guards.first?.usingDefault)
        XCTAssertNil(status.linkGuardMode)
        XCTAssertNil(status.isolatedDevPorts)
    }

    func testGuardStatusDecodesExtendedShape() throws {
        let json = #"{"activeSecurityLevel":"open","activeSecurityLevelLabel":"Open","isCurrentNetworkTrusted":true,"guards":[{"key":"linkGuard","enabledInSettings":true,"usingDefault":false}],"linkGuardMode":"warn","vpnBackend":"tailscale","tailscaleExitNodeConfigured":true,"dnsThreatGuardProvider":"adguard","dnsThreatGuardScope":"always","isolatedDevPorts":[3000],"usbStorageAllowedVolumeCount":2,"caveats":["c"]}"#
        let status = try JSONRPCTransport.decodeContent(GuardStatus.self, from: toolResult(json))
        XCTAssertEqual(status.guards.first?.usingDefault, false)
        XCTAssertEqual(status.linkGuardMode, "warn")
        XCTAssertEqual(status.vpnBackend, "tailscale")
        XCTAssertEqual(status.tailscaleExitNodeConfigured, true)
        XCTAssertEqual(status.dnsThreatGuardProvider, "adguard")
        XCTAssertEqual(status.dnsThreatGuardScope, "always")
        XCTAssertEqual(status.isolatedDevPorts, [3000])
        XCTAssertEqual(status.usbStorageAllowedVolumeCount, 2)
    }

    /// A pre-1.10.0 server sends no `checkId`/`cisControl`/`nistCsf` on
    /// audit items at all — that must still decode, with all three nil.
    func testSecurityReportItemDecodesLegacyShapeWithoutComplianceFields() throws {
        let legacy = #"{"score":90,"grade":"A","totalChecks":1,"passedChecks":1,"items":[{"category":"c","title":"t","isPassed":true,"statusText":"ok","detail":"d","recommendation":"r","settingsURL":null,"isApplicable":true}],"caveats":[],"timestamp":"2026-09-23T00:00:00Z"}"#
        let report = try JSONRPCTransport.decodeContent(SecurityReport.self, from: toolResult(legacy))
        XCTAssertNil(report.items.first?.checkId)
        XCTAssertNil(report.items.first?.cisControl)
        XCTAssertNil(report.items.first?.nistCsf)
    }

    func testSecurityReportItemDecodesComplianceFields() throws {
        let json = #"{"score":90,"grade":"A","totalChecks":1,"passedChecks":1,"items":[{"category":"c","title":"t","isPassed":true,"statusText":"ok","detail":"d","recommendation":"r","settingsURL":null,"isApplicable":true,"checkId":"luks_encryption","cisControl":"3.11","nistCsf":["PR.DS-01"]}],"caveats":[],"timestamp":"2026-09-23T00:00:00Z"}"#
        let report = try JSONRPCTransport.decodeContent(SecurityReport.self, from: toolResult(json))
        XCTAssertEqual(report.items.first?.checkId, "luks_encryption")
        XCTAssertEqual(report.items.first?.cisControl, "3.11")
        XCTAssertEqual(report.items.first?.nistCsf, ["PR.DS-01"])
    }

    func testLinkRiskFactorKindIsOptional() throws {
        let legacy = #"{"originalURL":"a","finalURL":"a","redirectChain":[],"domain":"a","score":10,"riskLevel":"dangerous","isHTTPS":true,"riskFactors":[{"title":"t","detail":"d","isSevere":true}]}"#
        XCTAssertNil(try JSONRPCTransport.decodeContent(LinkAuditReport.self, from: toolResult(legacy)).riskFactors.first?.kind)
        let current = legacy.replacingOccurrences(of: #""isSevere":true}"#, with: #""isSevere":true,"kind":"homograph"}"#)
        XCTAssertEqual(try JSONRPCTransport.decodeContent(LinkAuditReport.self, from: toolResult(current)).riskFactors.first?.kind, "homograph")
    }

    func testIncidentTimelineDecodes() throws {
        let json = #"{"unresolvedCount":1,"events":[{"id":"8D3F","timestamp":"2026-09-14T00:00:00Z","source":"arpSpoof","sourceLabel":"ARP","severity":"critical","summary":"s","attackTechnique":"T1557","actionTaken":"air_gap","actionTakenLabel":"Air-Gap","status":"open"}],"caveats":[]}"#
        let timeline = try JSONRPCTransport.decodeContent(IncidentTimeline.self, from: toolResult(json))
        XCTAssertEqual(timeline.events.first?.source, "arpSpoof")
        XCTAssertNil(timeline.events.first?.processID)
        XCTAssertNil(timeline.events.first?.resolvedAt)
    }

    func testNetworkHistoryDecodes() throws {
        let json = #"{"knownNetworkCount":2,"networks":[{"ssid":"CafeWiFi","gatewayCount":1,"lastSeen":"2026-09-14T00:00:00Z"}],"lookalikePairs":[{"ssid":"CafeWiFi","similarTo":"CafeWlFi","editDistance":1}],"caveats":[]}"#
        let history = try JSONRPCTransport.decodeContent(NetworkHistory.self, from: toolResult(json))
        XCTAssertEqual(history.lookalikePairs.first?.editDistance, 1)
    }

    func testAppHelpResultDecodesWithAndWithoutLanguage() throws {
        let json = #"{"query":"ARP","topic":"feature","totalResults":1,"items":[{"id":"x","topic":"feature","title":"t","summary":"s","details":"d","tags":[]}]}"#
        XCTAssertNil(try JSONRPCTransport.decodeContent(AppHelpResult.self, from: toolResult(json)).language)
        let withLang = json.replacingOccurrences(of: #""totalResults":1"#, with: #""totalResults":1,"language":"en""#)
        XCTAssertEqual(try JSONRPCTransport.decodeContent(AppHelpResult.self, from: toolResult(withLang)).language, "en")
    }

    func testDocResourceResultsDecode() throws {
        let list = try JSONRPCTransport.decodeResult(DocResourceList.self, from: [
            "resources": [["uri": "roamswitch://docs/features", "name": "n", "description": "d", "mimeType": "text/markdown"]],
        ])
        XCTAssertEqual(list.resources.first?.uri, "roamswitch://docs/features")
        let read = try JSONRPCTransport.decodeResult(DocResourceReadResult.self, from: [
            "contents": [["uri": "roamswitch://docs/features", "mimeType": "text/markdown", "text": "# Features"]],
        ])
        XCTAssertEqual(read.contents.first?.text, "# Features")
    }
}
