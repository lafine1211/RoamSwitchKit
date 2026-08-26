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

    func testSecurityReport() async throws {
        let client = try makeClientOrSkip()
        let report = try await client.securityReport()
        XCTAssertGreaterThanOrEqual(report.score, 0)
        XCTAssertGreaterThan(report.totalChecks, 0)
        XCTAssertEqual(report.totalChecks, report.items.count)
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
        XCTAssertEqual(status.guards.count, 4)
        XCTAssertFalse(status.activeSecurityLevel.isEmpty)
    }
}
