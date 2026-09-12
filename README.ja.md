# RoamSwitchKit

[English](README.md) | **日本語**

[RoamSwitch](https://lafine.net) がローカルで計算した Mac のネットワークセキュリティ診断結果を
読み取るための、読み取り専用 Swift クライアントです。

[![Swift](https://img.shields.io/badge/Swift-5.9%2B-orange)](https://swift.org)
[![Platform](https://img.shields.io/badge/platform-macOS%2012%2B-lightgrey)](https://lafine.net)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## RoamSwitch とは

[**RoamSwitch**](https://lafine.net) は、Mac のネットワーク境界を自動で防衛する macOS 用
メニューバーアプリです。カフェの Wi-Fi、カンファレンス会場のネットワーク、あるいは明示的に
信頼登録していないネットワークに接続した瞬間に、ファイアウォールを締め、ARP スプーフィングを
監視し、`0.0.0.0` で待ち受けたままの開発サーバーやデータベースを検出して警告します。
無料で利用でき、Pro 版ではワンクリック不要の自動対応（新規リスニングポートの自動遮断、ARP
スプーフィング検知時の自動隔離、USB ストレージ／Bluetooth ガード）が加わります。

具体的に、RoamSwitch は次を常時計算しています。

- **ネットワーク信頼度** — 現在の Wi-Fi / ゲートウェイが信頼登録済みか、また現在どの保護レベル
  （Open / Balanced / Lockdown）が適用されているか
- **ARP スプーフィング** — 中間者攻撃の兆候となるゲートウェイ MAC フィンガープリントの変化
- **外部公開ポート** — `localhost` を超えて待ち受けている全 TCP ポート。設定ミスが多い既知
  サービス（Redis、MongoDB、Elasticsearch、Docker、Memcached、`next dev` / Vite /
  `python -m http.server` などの開発サーバー、Ollama:11434 / LM Studio:1234 / Gradio:7860 /
  vLLM:8000 といったローカル AI 推論サーバー）と突き合わせ、危険な HTTP レスポンスも確認します
- **18 項目のローカルセキュリティ診断スコア** — FileVault、SIP、Gatekeeper、自動アップデート、
  XProtect、ファイアウォール、ステルスモード、Wi-Fi 暗号化強度、ARP スプーフィング、
  ゲートウェイ ARP 固定、SSH リモートログイン、sudo の `NOPASSWD` 監査、外部公開ポート、
  Web・メールダウンロード保護、DNS 脅威保護、フィッシング・リンク保護、USB / BadUSB ガード、
  macOS アクセサリ接続保護

RoamSwitch はこれと同じデータを、同梱の読み取り専用 MCP サーバー経由で AI アシスタント
（Claude Desktop、Claude Code、その他 [MCP](https://modelcontextprotocol.io) 対応クライアント）
にも提供しています（設定方法は [lafine.net/mcp-setup](https://lafine.net/mcp-setup.html)）。
**RoamSwitchKit は、その同じインターフェースを AI クライアントではなく Swift コードから
使えるようにしたもの**です。ARP 解析やポートスキャン、Wi-Fi 暗号化判定を自前で再実装すること
なく、「今このMacのネットワークは安全か？」を RoamSwitch が算出したそのままのデータで
取得できます。

想定用途: 未信頼ネットワークではバックグラウンド同期を止める同期アプリ、Open Wi-Fi では
自動ロックを短くするパスワードマネージャー、`0.0.0.0` バインド直前に警告する開発者ツール、
ネットワーク信頼度の変化に反応する Shortcuts / 自動化ワークフローなど。

## 設計方針

- **常に読み取り専用。** RoamSwitchKit は現在の診断結果を照会できるだけです。保護レベルの変更、
  ロックダウン切替、ポート隔離、デバイス取り出しを行う API は、このパッケージに一切存在しません。
  RoamSwitchKit をリンクしたアプリが他人の保護状態を変更する手段はなく、それができるのは
  ユーザー自身が操作する RoamSwitch 本体の UI だけです。これは v1 の未実装ではなく意図的な
  スコープ制限です。サードパーティのコードにセキュリティツールの保護設定への書き込み権を
  与えることは、全ユーザーの信頼モデルを損なうためです。
- **完全ローカル・ゼロテレメトリ。** 各呼び出しは RoamSwitch 同梱の `RoamSwitchMCPServer`
  バイナリをサブプロセスとして起動し、stdio で通信します。このパッケージのコードには
  ネットワークリクエストが 1 つもありません。RoamSwitchKit も RoamSwitch 本体も、何も
  送信しません。
- **新たな攻撃面を作らない。** RoamSwitchKit はソケットを開かず、サービスを登録せず、何も
  待ち受けません。プロセスを起動し、stdin にリクエストを書き、stdout から 1 件のレスポンスを
  読み、プロセスを終了させるだけです。

## 動作要件

- macOS 12 以降
- Swift 5.9 以降（Xcode 15 以降）
- コードを実行するマシンに [RoamSwitch](https://lafine.net) 1.3.0 以降がインストール済みで
  あること（本パッケージが通信する `RoamSwitchMCPServer` バイナリは、このリリースから同梱）

## インストール

`Package.swift` に追加します。

```swift
dependencies: [
    .package(url: "https://github.com/lafine1211/RoamSwitchKit.git", from: "1.0.0")
]
```

## 使い方

```swift
import RoamSwitchKit

let client = try RoamSwitchClient()

// 総合セキュリティ診断（FileVault、SIP、Gatekeeper、ファイアウォール、
// Wi-Fi 暗号化強度、ARP スプーフィング、外部公開ポート — 0〜100 でスコア化し、
// 不合格項目には改善アドバイスが付きます）。
let report = try await client.securityReport()
print(report.score, report.grade)

// localhost を超えて待ち受けている全ポート。既知の危険サービスや
// 危険な HTTP レスポンスの観点で監査済みです。
let ports = try await client.exposedPorts()
for port in ports.ports where port.overallRisk == "high" {
    print("\(port.processName) on port \(port.port): \(port.findings.first?.recommendation ?? "")")
}

// RoamSwitch の Pro 自動対応ガードが有効かどうか、および現在の
// ネットワークがユーザーの信頼リストに含まれるかどうか。
let status = try await client.guardStatus()
print(status.activeSecurityLevelLabel, status.isCurrentNetworkTrusted)

// メール中のリンク、短縮 URL、不審なドメインをフィッシング・Unicode
// ホモグラフ偽装・ブランド偽装の観点で診断します（Zero Telemetry）。
let urlReport = try await client.auditURLSafety(url: "https://apple.com.login-verify.xyz")
print(urlReport.score, urlReport.riskLevel) // 例: 20, "dangerous"

// 直近 N 時間の macOS 統合ログのセキュリティ事象（sudo / SSH / Gatekeeper /
// XProtect）と、ログパターン異常（この Mac で初めて観測されたパターン、
// またはこの期間だけ異常に多発しているパターン）。メッセージは RoamSwitch を
// 出る前に API キー・トークン・秘密鍵ヘッダーが検査・マスクされます。
let logAudit = try await client.auditSecurityLogs(hours: 24)
for anomaly in logAudit.templateAnomalies where anomaly.isNew {
    print("New log pattern: \(anomaly.template)")
}

// インストール済み Homebrew formula を、ネットワーク非依存のローカル
// CVE マップと照合します。
let pkgCve = try await client.packageCveScan()
for finding in pkgCve.findings {
    print("\(finding.package) \(finding.installedVersion): \(finding.cveId) (CVSS \(finding.cvssScore))")
}

// 同じ仕組みを言語エコシステムのロックファイル（npm / PyPI / crates.io 等）にも。
let langCve = try await client.packageCveScanLanguages(watchedFolders: ["/Users/me/code/my-app"])
print(langCve.scannedFolderCount, langCve.findings.count)

// ポート番号からの推測ではなく、公開中のサービスが実際に無認証で
// 応答するかを確認する実証型プローブ（オプトイン）。
let activeScan = try await client.activeVulnScan()
if activeScan.enabled {
    print(activeScan.findings.count, "confirmed finding(s)")
}

// ランサムウェア・カナリアガード: おとりファイルの状況と、直近 50 件までの
// 検知インシデント。ローカル状態のみを読むため、ネットワークが Air-Gap 中でも
// 動作します。
let canary = try await client.canaryStatus()
for incident in canary.recentIncidents {
    print(incident.timestamp, incident.fileName, incident.detectedAction)
}

// ポート異常ガード: 外部公開ポートで突然待ち受けを始めた未知の実行ファイルと、
// 自動遮断された履歴。
let portIncidents = try await client.portAnomalyIncidents()
print(portIncidents.autoIsolatedPorts)

// ランタイム脅威封じ込め（Linux 版の eBPF ランタイムガードに相当）:
// Apple 自身の XProtect がマルウェアを検知した時点で発火し、ネットワークを
// Air-Gap 隔離します。Air-Gap の発動理由を調べるにはまずこれを照会してください。
// 遮断中でもローカル LLM から参照できます。
let runtimeThreat = try await client.runtimeThreatStatus()
if runtimeThreat.isIsolated {
    print("Air-Gapped due to:", runtimeThreat.lastIncident?.message ?? "unknown")
}

// 通知履歴: 直近 7 日間に RoamSwitch が送信した通知（ログ監査の異常、
// ClickFix 検知など）を新しい順に返します。ローカル状態のみを読むため、
// ネットワークが Air-Gap 中でも動作します。
let notifications = try await client.notificationHistory()
for entry in notifications {
    print(entry.timestamp, entry.title)
}
```

すべての呼び出しは `async throws` で、`RoamSwitchClientError` を投げる可能性があります。
最も多いのは RoamSwitch が未インストールの場合の `.appNotInstalled` です。致命的エラーとして
扱うのではなく、機能を隠す・lafine.net を案内するなど、穏当に処理してください。

## 動作の仕組み

`RoamSwitchClient` は稼働中の RoamSwitch プロセスと直接通信するわけではありません。
各呼び出しは次の流れで動きます。

1. `NSWorkspace.urlForApplication(withBundleIdentifier:)`（既定のバンドル ID は
   `com.tetsuharu.RoamSwitch`）で RoamSwitch のインストール場所を解決し、その中の
   `Contents/MacOS/RoamSwitchMCPServer` を特定します。
2. そのバイナリを新規サブプロセスとして起動します。
3. 標準的な MCP ハンドシェイク（`initialize`、`notifications/initialized`）に続けて
   `tools/call` リクエストを、改行区切りの JSON-RPC 2.0 としてサブプロセスの stdin へ
   書き込みます。これは RoamSwitch が Claude Desktop / Code などの MCP クライアントと
   話すのと同じプロトコルです。
4. stdout から対応するレスポンス行を読み、JSON ペイロードを型付き Swift 構造体へデコードし、
   サブプロセスを終了させます。

これは意図的にステートレスな設計です。永続接続もデーモンも無く、呼び出し間に何も残りません。
そのため各呼び出しにはプロセス起動のオーバーヘッド（数十ミリ秒）と診断自体の所要時間が
かかります。特に `exposedPorts()` は、外部公開ポートが複数ある場合それぞれを個別にプローブ
するため数秒かかることがあります。

`RoamSwitchClient` は Swift の `actor` なので、同一インスタンスへの呼び出しは直列化されます。
1 つ作って使い回しても、呼び出しごとに作っても、どちらも安全です。

## API リファレンス

### `RoamSwitchClient`

```swift
public actor RoamSwitchClient {
    public init(appBundleID: String = "com.tetsuharu.RoamSwitch", timeout: TimeInterval = 30) throws
    public init(executableURL: URL, timeout: TimeInterval = 30) throws

    public func securityReport() async throws -> SecurityReport
    public func exposedPorts(includeLocalOnly: Bool = false) async throws -> ExposedPorts
    public func guardStatus() async throws -> GuardStatus
    public func auditURLSafety(url: String) async throws -> LinkAuditReport
    public func auditSecurityLogs(hours: Int = 24) async throws -> SecurityLogAudit
    public func activeVulnScan() async throws -> ActiveVulnScanResult
    public func packageCveScan() async throws -> PackageCveScanResult
    public func packageCveScanLanguages(watchedFolders: [String] = []) async throws -> PackageCveScanLanguagesResult
    public func canaryStatus() async throws -> CanaryStatus
    public func portAnomalyIncidents() async throws -> PortAnomalyIncidentsSummary
    public func runtimeThreatStatus() async throws -> RuntimeThreatStatus
    public func notificationHistory() async throws -> [NotificationHistoryEntry]
}
```

- `init(appBundleID:timeout:)` — RoamSwitch のインストールを解決・検証します。`appBundleID` を
  上書きするのは、別 ID のビルドに対してテストする場合だけにしてください。
- `init(executableURL:timeout:)` — 特定の `RoamSwitchMCPServer` バイナリを直接指定します
  （デバッグ、テスト、非標準インストールパス向け）。
- `timeout` — 1 呼び出しあたりの実時間上限（既定 30 秒）。超過するとサブプロセスを終了させ、
  `.timedOut` を投げます。ブロッキングするやり取りは Swift Concurrency の協調プールの外で
  実行されるため、他の `async` 処理を止めません。
- `securityReport()` — Mac のローカルセキュリティ総合診断（18 項目）を実行します。
- `exposedPorts(includeLocalOnly:)` — 待ち受け中の TCP ポートを列挙します。localhost を超えて
  公開されているものは常に完全監査されます。`includeLocalOnly: true` を渡すと localhost 限定
  ポートも含めます（こちらは時間のかかる個別監査なしで返ります）。
- `guardStatus()` — 現在の保護レベル、信頼ネットワーク判定、各オプションガードの ON/OFF。
- `auditURLSafety(url:)` — メールリンクや Web URL を、フィッシング、Unicode ホモグラフ偽装、
  ブランド偽装サブドメイン、高リスク TLD の観点で解析します（Zero Telemetry）。
- `auditSecurityLogs(hours:)` — 指定期間の macOS 統合ログのセキュリティ事象（sudo / SSH /
  Gatekeeper / XProtect）を監査し、ログパターン異常（新規パターン・頻度スパイク）を検出します。
  各メッセージは RoamSwitch を出る前に API キー・トークン・秘密鍵ヘッダーがマスクされます。
- `activeVulnScan()` — この Mac 自身の待ち受けポート（127.0.0.1 限定）に対して、実際に非破壊の
  プローブを送り、公開サービスが本当に無認証で応答するかを確認します。既定で無効
  （RoamSwitch の設定でオプトイン）。有効化するまでは `enabled: false` と空の結果を返します。
- `packageCveScan()` — インストール済み Homebrew formula を、RoamSwitch のネットワーク非依存
  ローカル CVE マップ（厳選した許可リストに対する実際の NVD データ）と照合します。
- `packageCveScanLanguages(watchedFolders:)` — 指定フォルダ配下の言語エコシステムの
  ロックファイル（npm / PyPI / crates.io など）を、同じローカル CVE マップと照合します。
- `canaryStatus()` — ランサムウェア・カナリアガード（Pro）。おとりファイル数と、直近 50 件
  までの検知インシデント。ローカル状態のみを読みます（Air-Gap 中も動作）。
- `portAnomalyIncidents()` — ポート異常ガード（Pro）。ベースライン／自動隔離中ポートの状態と、
  直近 50 件までのインシデント（外部公開ポートで待ち受けを始めた未知の実行ファイル）。
  ローカル状態のみを読みます（Air-Gap 中も動作）。
- `runtimeThreatStatus()` — ランタイム脅威封じ込め（Pro）。Apple の XProtect によるマルウェア
  検知が原因で現在 Air-Gap 隔離されているかどうかと、その発動元となった直近 1 件のインシデント。
  ローカル状態のみを読みます（Air-Gap 中も動作）。発動中の Air-Gap の原因を調べるなら、
  まずこれを照会してください。
- `notificationHistory()` — 直近 7 日間に RoamSwitch が送信した通知（ログ監査の異常、
  ClickFix 検知など）を新しい順に返します。ローカル状態のみを読みます（Air-Gap 中も動作）。

### 戻り値の型

各構造体のフィールド定義は英語版 README の
[API reference](README.md#api-reference) および [AGENTS.md](AGENTS.md) に、Swift の型宣言
そのままの形で掲載しています（`SecurityReport`、`ExposedPorts`、`GuardStatus`、
`LinkAuditReport`、`SecurityLogAudit`、`ActiveVulnScanResult`、`PackageCveScanResult`、
`PackageCveScanLanguagesResult`、`CanaryStatus`、`PortAnomalyIncidentsSummary`、
`RuntimeThreatStatus`、`NotificationHistoryEntry`、`RoamSwitchClientError`）。

### `RoamSwitchClientError`

| ケース | 意味 |
|---|---|
| `.appNotInstalled` | 指定バンドル ID のアプリが Launch Services に登録されていない |
| `.serverBinaryNotFound` | RoamSwitch はあるが 1.3.0 より前（バンドル内に `RoamSwitchMCPServer` が無い） |
| `.processLaunchFailed(underlying:)` | サブプロセスの起動自体に失敗した |
| `.noResponse` | レスポンスが届く前にサブプロセスの stdout が閉じた |
| `.timedOut` | `timeout` 内に応答が無く、サブプロセスを終了させた |
| `.invalidResponse(raw:)` | 応答はあったが、正しい／想定どおりの JSON-RPC ではなかった |
| `.toolError(message:)` | サーバーが JSON-RPC エラー、または `isError: true` のツール結果を返した |

すべてのケースが `LocalizedError` に準拠しているため、`error.localizedDescription` で
人間が読めるメッセージが得られます。

## 互換性について

RoamSwitch の診断ツールが返す JSON が、本パッケージとアプリ本体の実質的な契約です。
`Sources/RoamSwitchKit/Models.swift` はその形を独立してミラーしています。RoamSwitchKit は
非公開の RoamSwitch アプリリポジトリとは別の公開リポジトリであり、Swift の型を直接共有できない
ためです。将来の RoamSwitch リリースでレスポンス形状が変わる場合、本パッケージのモデルも
同時に更新されます。厳密に固定したい場合はバージョンをピンしてください。

## AI コーディングアシスタント向け

[AGENTS.md](AGENTS.md) に、API 全体を機械可読でコンパクトな形式でまとめています。
Claude Code、Cursor、Copilot などに本パッケージを組み込ませる際は、メソッド名・フィールド名の
ハルシネーションを避けるためにこれを参照させてください。

これが自動的に読み込まれるのは、アシスタントがこのリポジトリ内で直接作業している場合だけです。
RoamSwitchKit を依存関係として別プロジェクトに追加した場合は自動では見つからないので、
組み込みを依頼するときに次の URL を貼ってください:
`https://github.com/lafine1211/RoamSwitchKit/blob/main/AGENTS.md`

## ライセンス

MIT — [LICENSE](LICENSE) を参照してください。
