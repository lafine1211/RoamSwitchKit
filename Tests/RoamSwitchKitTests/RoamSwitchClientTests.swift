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
}
