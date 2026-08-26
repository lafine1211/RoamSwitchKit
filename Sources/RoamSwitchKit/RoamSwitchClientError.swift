import Foundation

public enum RoamSwitchClientError: Error, LocalizedError, Sendable, Equatable {
    /// No app with the given bundle identifier (default: com.tetsuharu.RoamSwitch)
    /// could be found via NSWorkspace. RoamSwitch is not installed, or was
    /// installed somewhere NSWorkspace can't resolve (e.g. not yet indexed
    /// by Launch Services).
    case appNotInstalled

    /// The RoamSwitchMCPServer binary was not found inside the resolved
    /// app bundle at Contents/MacOS/RoamSwitchMCPServer. Likely an app
    /// version older than 1.3.0, which shipped without it.
    case serverBinaryNotFound

    /// Launching the subprocess itself failed (e.g. Gatekeeper, permissions).
    case processLaunchFailed(underlying: Error)

    /// The subprocess exited or closed its pipe before returning a response
    /// to our request.
    case noResponse

    /// A response line was received but wasn't valid JSON-RPC, or its
    /// "result" shape didn't match what this tool call expects.
    case invalidResponse(raw: String)

    /// The server returned a JSON-RPC error object, or a tool result with
    /// isError: true.
    case toolError(message: String)

    public var errorDescription: String? {
        switch self {
        case .appNotInstalled:
            return "RoamSwitch.app isn't installed. RoamSwitchKit reads live diagnostics from the running app and can't function without it — see https://lafine.net to install."
        case .serverBinaryNotFound:
            return "RoamSwitch.app is installed but doesn't include RoamSwitchMCPServer. Update to RoamSwitch 1.3.0 or later."
        case .processLaunchFailed(let underlying):
            return "Failed to launch RoamSwitchMCPServer: \(underlying.localizedDescription)"
        case .noResponse:
            return "RoamSwitchMCPServer closed its output before responding."
        case .invalidResponse(let raw):
            return "RoamSwitchMCPServer returned an unexpected response: \(raw)"
        case .toolError(let message):
            return "RoamSwitchMCPServer reported an error: \(message)"
        }
    }

    // `Error` isn't Equatable, so `processLaunchFailed` can't be synthesized —
    // compare the other cases by value and treat any two launch failures as
    // equal regardless of their underlying error.
    public static func == (lhs: RoamSwitchClientError, rhs: RoamSwitchClientError) -> Bool {
        switch (lhs, rhs) {
        case (.appNotInstalled, .appNotInstalled),
             (.serverBinaryNotFound, .serverBinaryNotFound),
             (.noResponse, .noResponse),
             (.processLaunchFailed, .processLaunchFailed):
            return true
        case let (.invalidResponse(a), .invalidResponse(b)):
            return a == b
        case let (.toolError(a), .toolError(b)):
            return a == b
        default:
            return false
        }
    }
}
