import Foundation

/// Speaks the same newline-delimited JSON-RPC 2.0 stdio protocol that
/// RoamSwitchMCPServer implements for MCP clients (see
/// RoamSwitchMCPServer/main.swift in the main app repo). Launches a fresh
/// subprocess per call — stateless, matches the server's own
/// no-side-effects, nothing-persists design.
struct JSONRPCTransport {
    let executableURL: URL

    private static let initializeID = 1
    private static let toolCallID = 2

    func callTool(name: String, arguments: [String: Any]) throws -> [String: Any] {
        let process = Process()
        process.executableURL = executableURL

        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        process.standardInput = stdinPipe
        process.standardOutput = stdoutPipe
        process.standardError = Pipe() // discard; nothing we can act on

        do {
            try process.run()
        } catch {
            throw RoamSwitchClientError.processLaunchFailed(underlying: error)
        }
        defer {
            if process.isRunning {
                process.terminate()
            }
        }

        let stdin = stdinPipe.fileHandleForWriting
        let stdout = stdoutPipe.fileHandleForReading

        try writeLine(["jsonrpc": "2.0", "id": Self.initializeID, "method": "initialize", "params": [
            "protocolVersion": "2025-06-18",
            "capabilities": [String: Any](),
            "clientInfo": ["name": "RoamSwitchKit", "version": "1.0.0"],
        ]], to: stdin)

        try writeLine(["jsonrpc": "2.0", "method": "notifications/initialized"], to: stdin)

        try writeLine(["jsonrpc": "2.0", "id": Self.toolCallID, "method": "tools/call", "params": [
            "name": name,
            "arguments": arguments,
        ]], to: stdin)

        // Everything we're going to say has been said — closing our end of
        // stdin lets the server's `while let line = readLine()` loop reach
        // EOF and exit cleanly once it's drained the buffered requests.
        try? stdin.close()

        guard let responseData = try readLine(from: stdout, matchingID: Self.toolCallID) else {
            throw RoamSwitchClientError.noResponse
        }

        guard let message = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any] else {
            throw RoamSwitchClientError.invalidResponse(raw: String(data: responseData, encoding: .utf8) ?? "<undecodable>")
        }

        if let error = message["error"] as? [String: Any] {
            throw RoamSwitchClientError.toolError(message: error["message"] as? String ?? "unknown error")
        }

        guard let result = message["result"] as? [String: Any] else {
            throw RoamSwitchClientError.invalidResponse(raw: String(data: responseData, encoding: .utf8) ?? "<undecodable>")
        }

        if let isError = result["isError"] as? Bool, isError {
            throw RoamSwitchClientError.toolError(message: extractText(from: result) ?? "unknown tool error")
        }

        return result
    }

    static func decodeContent<T: Decodable>(_ type: T.Type, from result: [String: Any]) throws -> T {
        guard let text = extractText(from: result), let data = text.data(using: .utf8) else {
            throw RoamSwitchClientError.invalidResponse(raw: "\(result)")
        }
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw RoamSwitchClientError.invalidResponse(raw: text)
        }
    }

    // MARK: - Private helpers

    private func writeLine(_ object: [String: Any], to handle: FileHandle) throws {
        let data = try JSONSerialization.data(withJSONObject: object)
        handle.write(data)
        handle.write(Data([0x0A]))
    }

    /// Reads newline-delimited JSON-RPC messages from `handle`, discarding
    /// any whose "id" doesn't match `id` (e.g. the initialize response),
    /// until the matching line is found or the pipe reaches EOF.
    private func readLine(from handle: FileHandle, matchingID id: Int) throws -> Data? {
        var buffer = Data()
        while true {
            let chunk = handle.availableData
            if chunk.isEmpty {
                return nil // EOF before we saw our response
            }
            buffer.append(chunk)
            while let newlineIndex = buffer.firstIndex(of: 0x0A) {
                let line = buffer.subdata(in: buffer.startIndex..<newlineIndex)
                buffer.removeSubrange(buffer.startIndex...newlineIndex)
                if let parsed = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
                   let responseID = parsed["id"] as? Int, responseID == id {
                    return line
                }
            }
        }
    }
}

private func extractText(from result: [String: Any]) -> String? {
    (result["content"] as? [[String: Any]])?.first?["text"] as? String
}
