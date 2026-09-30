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

    /// Upper bound for a single newline-delimited response line (16 MiB).
    static let maxResponseLineBytes = 16 * 1024 * 1024

    private static let initializeID = 1
    private static let toolCallID = 2

    /// `tools/call` — additionally maps a tool result with `isError: true`
    /// to `.toolError`.
    func callTool(name: String, arguments: [String: Any]) throws -> [String: Any] {
        let result = try request(method: "tools/call", params: [
            "name": name,
            "arguments": arguments,
        ])
        if let isError = result["isError"] as? Bool, isError {
            throw RoamSwitchClientError.toolError(message: extractText(from: result) ?? "unknown tool error")
        }
        return result
    }

    /// Any single JSON-RPC request after the MCP handshake (e.g.
    /// `resources/list`, `resources/read`). Returns the raw `result` object;
    /// a JSON-RPC `error` object throws `.toolError`.
    func request(method: String, params: [String: Any]) throws -> [String: Any] {
        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()

        // Spawn in its *own process group* (posix_spawn, not Process) so that on
        // timeout we can SIGKILL the server together with anything it spawned
        // (nmap, npm, ...), instead of orphaning those children.
        let pid: pid_t
        do {
            pid = try Self.spawnInOwnProcessGroup(
                executablePath: executableURL.path,
                stdinFD: stdinPipe.fileHandleForReading.fileDescriptor,
                stdoutFD: stdoutPipe.fileHandleForWriting.fileDescriptor
            )
        } catch {
            throw RoamSwitchClientError.processLaunchFailed(underlying: error)
        }
        // The child owns these ends now; closing ours lets EOF propagate.
        try? stdinPipe.fileHandleForReading.close()
        try? stdoutPipe.fileHandleForWriting.close()

        // Watchdog: if the exchange overruns `timeout`, kill the whole process
        // group. That collapses the blocking read below to EOF, and the
        // `didTimeOut` flag lets us report it as `.timedOut` rather than
        // `.noResponse`. `reaped` guards against signalling a recycled pid.
        let stateLock = NSLock()
        var didTimeOut = false
        var reaped = false
        let watchdog = DispatchWorkItem {
            stateLock.lock()
            if !reaped {
                didTimeOut = true
                kill(-pid, SIGKILL)
            }
            stateLock.unlock()
        }
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + timeout, execute: watchdog)

        defer {
            watchdog.cancel()
            stateLock.lock()
            if !reaped {
                // Response (if any) is already read: tear down the group and reap.
                kill(-pid, SIGKILL)
                var status: Int32 = 0
                while waitpid(pid, &status, 0) == -1 && errno == EINTR {}
                reaped = true
            }
            stateLock.unlock()
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

            try writeLine(["jsonrpc": "2.0", "id": Self.toolCallID, "method": method, "params": params], to: stdin)

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
            throw RoamSwitchClientError.invalidResponse(raw: RoamSwitchClientError.truncatedRaw(String(data: responseData, encoding: .utf8) ?? "<undecodable>"))
        }

        if let error = message["error"] as? [String: Any] {
            throw RoamSwitchClientError.toolError(message: error["message"] as? String ?? "unknown error")
        }

        guard let result = message["result"] as? [String: Any] else {
            throw RoamSwitchClientError.invalidResponse(raw: RoamSwitchClientError.truncatedRaw(String(data: responseData, encoding: .utf8) ?? "<undecodable>"))
        }

        return result
    }

    static func decodeContent<T: Decodable>(_ type: T.Type, from result: [String: Any]) throws -> T {
        guard let text = extractText(from: result), let data = text.data(using: .utf8) else {
            throw RoamSwitchClientError.invalidResponse(raw: RoamSwitchClientError.truncatedRaw("\(result)"))
        }
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw RoamSwitchClientError.invalidResponse(raw: RoamSwitchClientError.truncatedRaw(text))
        }
    }

    /// Decodes a raw JSON-RPC `result` object (not a tool's text content) —
    /// used for `resources/list` / `resources/read`.
    static func decodeResult<T: Decodable>(_ type: T.Type, from result: [String: Any]) throws -> T {
        guard let data = try? JSONSerialization.data(withJSONObject: result) else {
            throw RoamSwitchClientError.invalidResponse(raw: RoamSwitchClientError.truncatedRaw("\(result)"))
        }
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw RoamSwitchClientError.invalidResponse(raw: RoamSwitchClientError.truncatedRaw(String(data: data, encoding: .utf8) ?? "\(result)"))
        }
    }

    // MARK: - Private helpers

    /// posix_spawn with: stdin/stdout wired to the given pipe ends, stderr to
    /// /dev/null (see note in `request`), a new process group led by the child,
    /// and every other inherited fd closed (POSIX_SPAWN_CLOEXEC_DEFAULT).
    private static func spawnInOwnProcessGroup(executablePath: String, stdinFD: Int32, stdoutFD: Int32) throws -> pid_t {
        var fileActions: posix_spawn_file_actions_t? = nil
        var attr: posix_spawnattr_t? = nil
        guard posix_spawn_file_actions_init(&fileActions) == 0 else { throw POSIXError(.ENOMEM) }
        defer { posix_spawn_file_actions_destroy(&fileActions) }
        guard posix_spawnattr_init(&attr) == 0 else { throw POSIXError(.ENOMEM) }
        defer { posix_spawnattr_destroy(&attr) }

        posix_spawn_file_actions_adddup2(&fileActions, stdinFD, 0)
        posix_spawn_file_actions_adddup2(&fileActions, stdoutFD, 1)
        posix_spawn_file_actions_addopen(&fileActions, 2, "/dev/null", O_WRONLY, 0)
        posix_spawnattr_setpgroup(&attr, 0)
        posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT))

        let argv: [UnsafeMutablePointer<CChar>?] = [strdup(executablePath), nil]
        var envp: [UnsafeMutablePointer<CChar>?] = ProcessInfo.processInfo.environment.map { strdup("\($0.key)=\($0.value)") }
        envp.append(nil)
        defer {
            for p in argv { free(p) }
            for p in envp { free(p) }
        }

        var pid: pid_t = 0
        let rc = posix_spawn(&pid, executablePath, &fileActions, &attr, argv, envp)
        guard rc == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: rc) ?? .EINVAL)
        }
        return pid
    }

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
            if buffer.count > Self.maxResponseLineBytes && !buffer.contains(0x0A) {
                throw RoamSwitchClientError.invalidResponse(raw: "response line exceeds \(Self.maxResponseLineBytes / (1024 * 1024)) MiB limit")
            }
            while let newlineIndex = buffer.firstIndex(of: 0x0A) {
                let line = buffer.subdata(in: buffer.startIndex..<newlineIndex)
                buffer.removeSubrange(buffer.startIndex...newlineIndex)
                if line.count > Self.maxResponseLineBytes {
                    throw RoamSwitchClientError.invalidResponse(raw: "response line exceeds \(Self.maxResponseLineBytes / (1024 * 1024)) MiB limit")
                }
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
