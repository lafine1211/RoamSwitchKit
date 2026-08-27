import Foundation

/// Speaks the same newline-delimited JSON-RPC 2.0 stdio protocol that
/// RoamSwitchMCPServer implements for MCP clients (see
/// RoamSwitchMCPServer/main.swift in the main app repo). Launches a fresh
/// subprocess per call — stateless, matches the server's own
/// no-side-effects, nothing-persists design.
///
/// All I/O here is synchronous and blocking; `RoamSwitchClient` is
/// responsible for running `callTool` off the Swift Concurrency cooperative
/// pool so a slow scan can't stall unrelated `async` work.
struct JSONRPCTransport: Sendable {
    let executableURL: URL
    /// Wall-clock ceiling for the whole exchange. If the server hasn't
    /// answered by then it is terminated and `callTool` throws `.timedOut`,
    /// rather than blocking the caller indefinitely.
    let timeout: TimeInterval

    init(executableURL: URL, timeout: TimeInterval = 30) {
        self.executableURL = executableURL
        self.timeout = timeout
    }

    private static let initializeID = 1
    private static let toolCallID = 2

    func callTool(name: String, arguments: [String: Any]) throws -> [String: Any] {
        let process = Process()
        process.executableURL = executableURL

        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        process.standardInput = stdinPipe
        process.standardOutput = stdoutPipe
        // Genuinely discard stderr. A bare `Pipe()` here would *buffer* the
        // server's stderr (e.g. its startup NSUserDefaults warning) with no
        // reader draining it — once that 64 KB pipe buffer filled, the server
        // would block on `write(2)` and this exchange would deadlock.
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            throw RoamSwitchClientError.processLaunchFailed(underlying: error)
        }

        // Watchdog: if the exchange overruns `timeout`, kill the subprocess.
        // That collapses the blocking read below to EOF, and the `didTimeOut`
        // flag lets us report it as `.timedOut` rather than `.noResponse`.
        let stateLock = NSLock()
        var didTimeOut = false
        let watchdog = DispatchWorkItem {
            stateLock.lock()
            didTimeOut = true
            stateLock.unlock()
            process.terminate()
        }
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + timeout, execute: watchdog)

        defer {
            watchdog.cancel()
            if process.isRunning {
                process.terminate()
            }
        }

        let stdin = stdinPipe.fileHandleForWriting
        let stdout = stdoutPipe.fileHandleForReading

        func timedOut() -> Bool {
            stateLock.lock()
            defer { stateLock.unlock() }
            return didTimeOut
        }

        do {
            try writeLine(["jsonrpc": "2.0", "id": Self.initializeID, "method": "initialize", "params": [
                "protocolVersion": "2025-06-18",
                "capabilities": [String: Any](),
                "clientInfo": ["name": "RoamSwitchKit", "version": RoamSwitchKitVersion.current],
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
        } catch {
            // A broken pipe here means the server exited before it could read
            // the request — treat it the same as an empty response.
            throw timedOut() ? RoamSwitchClientError.timedOut : RoamSwitchClientError.noResponse
        }

        guard let responseData = try readResponseLine(from: stdout, matchingID: Self.toolCallID) else {
            throw timedOut() ? RoamSwitchClientError.timedOut : RoamSwitchClientError.noResponse
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
        // `write(contentsOf:)` *throws* on a broken pipe; the older
        // `write(_ data: Data)` raises an uncatchable Objective-C exception
        // that would abort the host process instead.
        try handle.write(contentsOf: data)
        try handle.write(contentsOf: Data([0x0A]))
    }

    /// Reads newline-delimited JSON-RPC messages from `handle`, discarding
    /// any whose "id" doesn't match `id` (e.g. the initialize response),
    /// until the matching line is found or the pipe reaches EOF.
    private func readResponseLine(from handle: FileHandle, matchingID id: Int) throws -> Data? {
        var buffer = Data()
        while true {
            // `read(upToCount:)` throws on error; `availableData` would raise
            // an uncatchable Objective-C exception instead. An empty/nil
            // return means EOF.
            let chunk: Data?
            do {
                chunk = try handle.read(upToCount: 64 * 1024)
            } catch {
                return nil // treat a read error the same as EOF-before-response
            }
            guard let chunk, !chunk.isEmpty else {
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
