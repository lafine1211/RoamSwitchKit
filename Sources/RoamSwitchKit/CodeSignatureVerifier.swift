import Foundation
import Security

/// Verifies that code we are about to execute is signed by the RoamSwitch
/// developer team (Apple-anchored chain + Team ID pin), so a planted or
/// look-alike app / binary is never launched with the caller's privileges.
///
/// Note: check-then-launch has an inherent TOCTOU window if the attacker can
/// rewrite the binary between verification and `posix_spawn`; installing the
/// app to a root-owned location (/Applications) closes it.
enum CodeSignatureVerifier {
    static let teamID = "GV76B6G4YU"

    /// - Parameter extraRequirement: additional code-requirement clause, e.g.
    ///   `identifier "com.tetsuharu.RoamSwitch"`.
    static func isSignedByRoamSwitch(at url: URL, extraRequirement: String? = nil) -> Bool {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(rawValue: 0), &staticCode) == errSecSuccess,
              let code = staticCode else { return false }

        var text = "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
        if let extraRequirement { text += " and " + extraRequirement }

        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, SecCSFlags(rawValue: 0), &requirement) == errSecSuccess,
              let requirement else { return false }

        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate)
        return SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess
    }
}
