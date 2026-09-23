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
  あること（本パッケージが通信する `RoamSwitchMCPServer` バイナリは、このリリースから同梱）。
  より新しいリリースが必要なメソッドもあります（[メソッドごとの必要バージョン](#メソッドごとの必要バージョン)
  参照）。インストール済みアプリが未対応のメソッドを呼ぶと、サーバーが "Unknown tool" を返し
  `RoamSwitchClientError.toolError` になります。

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

// テキスト・ファイル・ディレクトリの機密情報漏洩スキャン（検出値はマスク済み）。
let secrets = try await client.auditSecrets(path: "/Users/me/code/my-app")
print(secrets.findings.map(\.type))

// マルウェア隔離 Vault の中身。
let vault = try await client.quarantineStatus()
print(vault.files.count, "quarantined file(s)")

// 同梱ナレッジベースの検索。`topic` の識別子は言語非依存で、結果は RoamSwitch の
// 現在の表示言語で返ります。
let help = try await client.appHelp(query: "Helper not connected", topic: .troubleshooting)
print(help.items.first?.recommendation ?? "")

// ARP スプーフィング・ランサムウェア・カナリア・ランタイム脅威・ポート異常の封じ込めを
// 1 本の時系列で。ARP 封じ込めの記録はここにしかありません。（RoamSwitch 1.9.25 以降）
let timeline = try await client.incidentTimeline(limit: 20)
for event in timeline.events where event.status == "open" {
    print(event.timestamp, event.source, event.summary)
}

// 過去に接続した Wi-Fi と、名前が酷似した Evil Twin 候補の SSID の組。
// ゲートウェイの MAC アドレスは返しません。（RoamSwitch 1.9.25 以降）
let networks = try await client.networkHistory()
for pair in networks.lookalikePairs {
    print("\(pair.ssid) looks like \(pair.similarTo)")
}

// 同梱の roamswitch://docs/* Markdown ドキュメント（MCP リソース）。
for doc in try await client.docResources() {
    print(doc.uri, doc.name)
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
    public func auditSecrets(text: String) async throws -> SecretAuditResult
    public func auditSecrets(path: String) async throws -> SecretAuditResult
    public func quarantineStatus() async throws -> QuarantineStatus
    public func appHelp(query: String? = nil, topic: AppHelpTopic? = nil) async throws -> AppHelpResult
    public func incidentTimeline(limit: Int = 50) async throws -> IncidentTimeline
    public func networkHistory(limit: Int = 50) async throws -> NetworkHistory
    public func docResources() async throws -> [DocResource]
    public func readDocResource(uri: String) async throws -> DocResourceContent
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
- `auditSecrets(text:)` / `auditSecrets(path:)` — テキスト、または絶対パスのファイル /
  ディレクトリ（再帰）から、露出した API キー（OpenAI、Anthropic、GitHub、AWS、HuggingFace、
  Google AI/Gemini、Slack、Stripe）と SSH/RSA 秘密鍵を検出します。検出値はマスクされます。
  存在しないパスは `.toolError` になります。ネットワーク通信なし。
- `quarantineStatus()` — マルウェア隔離 Vault の中身（元パス、ClamAV の脅威名、隔離日時、サイズ）。
  ファイルは移動されるだけで削除されません。ローカル状態のみを読みます。
- `appHelp(query:topic:)` — 同梱ナレッジベース（機能・アラート文言・設定・トラブルシューティング）
  を検索します。`query` はどの言語でも、アラート文言の一部でも構いません。`topic`
  （`AppHelpTopic`）は言語非依存の識別子です。内容は RoamSwitch の現在の表示言語で返ります。
- `incidentTimeline(limit:)` — ARP スプーフィング自動封じ込め、ランサムウェア・カナリアガード、
  ランタイム脅威封じ込め、ポート異常ガードを横断した時系列（新しい順、1〜200 件）。ARP 封じ込めの
  記録はここにしかありません。ローカル状態のみを読みます（Air-Gap 中も動作）。
- `networkHistory(limit:)` — 常時稼働の Evil Twin 検知が記憶しているネットワーク履歴。SSID ごとの
  ゲートウェイ機器数と最終接続日時（MAC アドレスは返しません）と、共通のゲートウェイを持たないのに
  名前が酷似した SSID の組。ローカル状態のみを読みます。
- `docResources()` / `readDocResource(uri:)` — 同梱の `roamswitch://docs/*` Markdown
  ドキュメントを一覧・取得します（MCP の `resources/list` / `resources/read`）。存在しない URI は
  `.toolError` になります。

### メソッドごとの必要バージョン

| メソッド | 必要な RoamSwitch |
|---|---|
| `securityReport()`、`exposedPorts(includeLocalOnly:)`、`guardStatus()`、`auditURLSafety(url:)` | 1.3.0 以降 |
| `appHelp(query:topic:)`、`docResources()`、`readDocResource(uri:)` | 1.4.4 以降 |
| `auditSecrets(text:)`、`auditSecrets(path:)`、`auditSecurityLogs(hours:)`、`quarantineStatus()`、`activeVulnScan()`、`packageCveScan()`、`packageCveScanLanguages(watchedFolders:)`、`canaryStatus()` | 1.8.9 以降 |
| `portAnomalyIncidents()`、`runtimeThreatStatus()` | 1.9.2 以降 |
| `notificationHistory()` | 1.9.8 以降 |
| `incidentTimeline(limit:)`、`networkHistory(limit:)` | 1.9.25 以降 |
| `GuardStatus` の拡張フィールド（`usingDefault`、`linkGuardMode`、`vpnBackend` など）と `LinkRiskFactor.kind` | 1.9.25 以降（それより前のアプリでは `nil`） |
| `ActiveVulnScanResult.confirmedSafe` / `.inconclusive`（`ScanCheckOutcome`） | 1.9.28 以降（それより前のアプリでは `nil`） |
| `SecurityAuditItem.checkId` / `.cisControl` / `.nistCsf` | 1.10.0 以降（それより前のアプリでは `nil`） |

### `SecurityReport`

| フィールド | 型 | 説明 |
|---|---|---|
| `score` | `Int` | 0〜100 の総合スコア |
| `grade` | `String` | `score` から算出したランク |
| `totalChecks` | `Int` | 診断項目数 |
| `passedChecks` | `Int` | 合格した項目数 |
| `items` | `[SecurityAuditItem]` | 項目ごとの結果 |
| `caveats` | `[String]` | このツールで完全には確認できなかった点の注記（例: 位置情報の権限を持てない単体 CLI プロセスでは Wi-Fi の SSID を読めない） |

`SecurityAuditItem`: `category`、`title`、`isPassed: Bool`、`statusText`、`detail`、`recommendation`、`settingsURL: String?`、`isApplicable: Bool`、`checkId: String?`（安定した機械可読識別子。例: `"luks_encryption"`。1.10.0 より前は `nil`）、`cisControl: String?`（確信を持ってマッピングできる場合の CIS Controls v8 セーフガード番号。`nil` は「マッピング無し」または旧バージョンのいずれか）、`nistCsf: [String]?`（NIST CSF 2.0 サブカテゴリコード。例: `["PR.DS-01"]`。同じ「確信があるものだけ・不明なら省略」方針）。

### `ExposedPorts`

| フィールド | 型 | 説明 |
|---|---|---|
| `isFirewallShielded` | `Bool` | 現在の保護レベルがすべての受信接続を遮断しているか |
| `ports` | `[ExposedPort]` | 待ち受け中の TCP ポートごとのエントリ |

`ExposedPort`: `processName`、`pid: Int`、`port: Int`、`isGloballyExposed: Bool`、`executablePath: String?`、`auditPerformed: Bool`、`overallRisk: String?`（`"low"` / `"medium"` / `"high"` / `"critical"`。`auditPerformed` のときのみ）、`findings: [PortFinding]`、`httpHeaders: [String: String]?`。

`PortFinding`: `title`、`riskLevel: String`、`description`、`recommendation`。

### `GuardStatus`

| フィールド | 型 | 説明 |
|---|---|---|
| `activeSecurityLevel` | `String` | 保護レベルの識別子（`"open"` / `"balanced"` / `"lockdown"`） |
| `activeSecurityLevelLabel` | `String` | ローカライズ済みの表示名 |
| `isCurrentNetworkTrusted` | `Bool` | 現在のゲートウェイが保存済みの信頼ネットワークと一致するか |
| `guards` | `[GuardEntry]` | ガード設定ごとのエントリ。1.9.25 以降は 22 件: `portAnomalyGuard`、`arpSpoofAutoContainment`、`usbKeyboardGuard`、`usbStorageGuard`、`bluetoothGuard`、`webMailDownloadGuard`、`dnsThreatGuard`、`runtimeThreatContainment`、`ransomwareCanaryGuard`、`clickFixGuard`、`dockerEventGuard`、`criticalPathFim`、`persistenceMonitor`、`gatewayARPLock`、`scheduledLogAudit`、`secretLeakClipboardAuditor`、`airGapAutoWiFiKill`、`wireGuardVPN`、`tailscaleKillSwitch`、`linkGuard`、`linkGuardFeedUpdates`、`activeVulnScan`。それより前のアプリは先頭 8 件のみ。今後も増える前提で扱ってください |
| `caveats` | `[String]` | 注記: `enabledInSettings` は設定のトグル状態のみ（実際の動作は Pro ライセンス状態にも依存し、別プロセスからは確認不可）、一部のガードは Pro 有効化時に一度だけ自動でオンになる、VPN トンネル / キルスイッチの実際の状態は読めない、など |
| `linkGuardMode` | `String?` | `"off"` / `"warn"`（接続を一時停止して確認。応答がなければ遮断） / `"block"`。1.9.25 以降 |
| `vpnBackend` | `String?` | `"wireguard"` / `"tailscale"`。1.9.25 以降 |
| `tailscaleExitNodeConfigured` | `Bool?` | Tailscale の Exit Node が選択済みか。1.9.25 以降 |
| `dnsThreatGuardProvider` | `String?` | `"quad9"` / `"cloudflareSecurity"` / `"adguard"` / `"cleanBrowsing"`。1.9.25 以降 |
| `dnsThreatGuardScope` | `String?` | `"awayOnly"` / `"always"`。1.9.25 以降 |
| `isolatedDevPorts` | `[Int]?` | ユーザーが LAN から隔離した開発サーバーのポート（昇順）。1.9.25 以降 |
| `usbStorageAllowedVolumeCount` | `Int?` | USB ストレージ許可リストの件数。1.9.25 以降 |

`GuardEntry`: `key: String`、`enabledInSettings: Bool`、`usingDefault: Bool?`（`true` = ユーザーが一度も切り替えておらず、値はそのガードの既定値。1.9.25 より前は `nil`）。

### `LinkAuditReport`

| フィールド | 型 | 説明 |
|---|---|---|
| `originalURL` | `String` | 渡された URL |
| `finalURL` | `String` | リダイレクト追跡後の URL |
| `redirectChain` | `[String]` | `originalURL` から `finalURL` までの各ホップ |
| `domain` | `String` | 最終到達先のドメイン |
| `score` | `Int` | 0〜100（100 = 安全、50 未満 = 危険） |
| `riskLevel` | `String` | `"safe"` / `"caution"` / `"dangerous"` |
| `isHTTPS` | `Bool` | 最終 URL が HTTPS か |
| `riskFactors` | `[LinkRiskFactor]` | 個別の検出内容（Unicode ホモグラフ偽装、ブランド名サブドメイン偽装、高リスク TLD、平文 HTTP など） |

`LinkRiskFactor`: `title`、`detail`、`isSevere: Bool`、`kind: String?` — 言語非依存の識別子（`"invalidURL"`、`"plaintextHTTP"`、`"ipAddressHost"`、`"homograph"`、`"brandSubdomainSpoofing"`、`"highRiskTLD"`、`"nonStandardPort"`、`"phishingPathKeyword"`。1.9.25 より前は `nil`）。`title` / `detail` は RoamSwitch の表示言語でローカライズされるため、判定には `title` ではなく `kind` を使ってください。

### `SecurityLogAudit`

| フィールド | 型 | 説明 |
|---|---|---|
| `timeWindowHours` | `Int` | 指定した期間（そのまま返却） |
| `totalEvents` | `Int` | `events.count` |
| `sudoFailures` | `Int` | 期間内の sudo 認証失敗数 |
| `sshAttempts` | `Int` | 期間内の SSH 接続試行数 |
| `gatekeeperBlocks` | `Int` | 期間内の Gatekeeper 遮断数 |
| `xprotectDetections` | `Int` | 期間内の XProtect マルウェア検知数 |
| `isClean` | `Bool` | sudo 失敗・Gatekeeper 遮断・XProtect 検知がいずれもない |
| `events` | `[SecurityLogEvent]` | 該当したログ事象（新しい順） |
| `templateAnomalies` | `[TemplateAnomaly]` | 新規または頻度外れ値と判定されたログパターン（下記） |

`SecurityLogEvent`: `timestamp: String`（ISO 8601）、`process`、`category: String`（`"sudo"` / `"ssh"` / `"gatekeeper"` / `"xprotect"` / `"auth"`）、`severity: String`（`"info"` / `"warning"` / `"critical"`）、`message`（API キー・トークン・秘密鍵ヘッダーを検査・マスク済み）。

`TemplateAnomaly`: この Mac で初めて観測されたログパターン、または指定期間内に通常より大幅に多発しているパターン（固定しきい値ではなく統計的な外れ値）— `template`（IP・16 進・数値などの可変部分を `<IP>` / `<HEX>` / `<NUM>` にマスクしたメッセージ）、`example`（このテンプレートに一致した実メッセージ 1 件。マスク済み）、`count: Int`、`zScore: Double`（`isNew` のときは 0。3.0 超で頻度スパイクと判定）、`isNew: Bool`。

### `ActiveVulnScanResult`

| フィールド | 型 | 説明 |
|---|---|---|
| `enabled` | `Bool` | ユーザーが設定でこの機能をオプトインしているか |
| `scannedTargetCount` | `Int` | プローブしたポート数 |
| `findings` | `[ActiveVulnScanFinding]` | 非破壊で確認できた検出結果。`enabled` が `false` なら空 |
| `confirmedSafe` | `[ScanCheckOutcome]?` | 確認が完了し、問題が見つからなかったチェック。1.9.28 より前は `nil` |
| `inconclusive` | `[ScanCheckOutcome]?` | 接続できず・タイムアウト等で確認自体ができなかったチェック（安全の確認ではない）。1.9.28 より前は `nil` |
| `message` | `String` | 人間向けの要約（ローカライズ済み） |

`ActiveVulnScanFinding`: `port: Int`、`processName`、`title`、`description`、`recommendation`。

`ScanCheckOutcome`（1.9.28 以降）: `port: Int`、`processName`、`check: String`（そのチェックの finding と同じタイトル）。`findings` が空というだけでは「全対象を確認して安全だった」のか「一部は確認自体できなかった」のかを区別できないため、安全と判断する前に必ず `inconclusive` を確認してください。

### `PackageCveScanResult`

| フィールド | 型 | 説明 |
|---|---|---|
| `mapInstalled` | `Bool` | 実データ入りのローカル CVE マップがインストール済みか。`false` は「該当なし」ではなく「データ未取得」 |
| `mapVersion` | `String` | インストール済み CVE マップのバージョン |
| `findings` | `[PackageCveFinding]` | 既知 CVE に該当したインストール済みパッケージ |

`PackageCveFinding`: `cveId`、`package`、`installedVersion`、`cvssScore: Double`、`fixedVersion`、`summary`、`confidence: String`（`"confirmed"` = formula→CPE 対応を個別に確認済み、`"gray"` = 未確認の完全一致キーワード照合。誤検知の可能性あり）。

### `PackageCveScanLanguagesResult`

| フィールド | 型 | 説明 |
|---|---|---|
| `scannedFolderCount` | `Int` | `watchedFolders` で渡したフォルダ数 |
| `findings` | `[PackageCveLanguageFinding]` | 既知 CVE に該当したロックファイル上の依存 |

`PackageCveLanguageFinding`: `ecosystem`（例: `"npm"`、`"PyPI"`、`"crates.io"`）、`cveId`、`package`、`installedVersion`、`cvssScore: Double`、`fixedVersion`、`summary`。

### `CanaryStatus`

| フィールド | 型 | 説明 |
|---|---|---|
| `isEnabled` | `Bool` | 設定でランサムウェア・カナリアガードがオンか |
| `monitoredFilesCount` | `Int` | 想定するおとりファイルのうち、現在ディスク上に存在する数 |
| `expectedFilesCount` | `Int` | 想定するおとりファイルの総数 |
| `recentIncidentsAvailable` | `Bool` | ガードが一度でも動作していれば `true`（履歴はアプリ本体がディスクに保存するため、別プロセスからも読める） |
| `recentIncidents` | `[CanaryIncident]` | 直近 50 件までの検知インシデント（新しい順） |

`CanaryIncident`: `timestamp: String`（ISO 8601）、`fileName`、`detectedAction`（削除・リネーム・改ざんなど）、`suspectedProcess: String?`、`affectedFilePaths: [String]`（同時に影響を受けた可能性のある実ファイル。ベストエフォート）。

### `PortAnomalyIncidentsSummary`

| フィールド | 型 | 説明 |
|---|---|---|
| `isEnabled` | `Bool` | 設定でポート異常ガードがオンか |
| `baselineCaptured` | `Bool` | 既知の待ち受け実行ファイルのベースライン取得が完了しているか |
| `autoIsolatedPorts` | `[Int]` | このガードが現在 LAN から自動隔離しているポート |
| `incidents` | `[PortAnomalyIncident]` | 直近 50 件までの検知インシデント（新しい順） |

`PortAnomalyIncident`: `timestamp: String`（ISO 8601）、`port: Int`、`processName`、`pid: Int`、`executablePath: String?`。

### `RuntimeThreatStatus`

Linux 版クライアントの eBPF ランタイムガードに相当します。Apple 自身の XProtect がファイルを
マルウェアと判定した時点で発火し（このアプリは生の exec 監視に必要な EndpointSecurity
エンタイトルメントを持ちません）、ネットワークを Air-Gap 隔離します。履歴配列ではなく、直近 1 件の
インシデントのみを保持します。

| フィールド | 型 | 説明 |
|---|---|---|
| `isEnabled` | `Bool` | 設定でランタイム脅威封じ込めがオンか |
| `isIsolated` | `Bool` | それによってこの Mac が現在ネットワーク隔離（Air-Gap）されているか |
| `lastContainmentDate` | `String?` | 直近の封じ込め日時（ISO 8601） |
| `lastIncident` | `SecurityLogEvent?` | 発動元となった XProtect 検知 |

### `NotificationHistoryEntry`

| フィールド | 型 | 説明 |
|---|---|---|
| `timestamp` | `String` | ISO 8601。文字列順に並べると時系列順になります |
| `title` | `String` | 通知のタイトル |
| `body` | `String` | 通知の本文 |

### `SecretAuditResult`

| フィールド | 型 | 説明 |
|---|---|---|
| `findings` | `[SecretFinding]` | 検出した機密情報ごとのエントリ |

`SecretFinding`: `type`（検出器の識別子）、`lineNumber: Int`、`masked`（大半をマスクした検出値。生の値は RoamSwitch の外に出ません）、`entropy: Double`（シャノンエントロピー）、`filePath: String?`（パスをスキャンした場合）。

### `QuarantineStatus`

| フィールド | 型 | 説明 |
|---|---|---|
| `quarantineDirectory` | `String` | Vault の絶対パス |
| `files` | `[QuarantinedFile]` | 現在隔離中のファイル |

`QuarantinedFile`: `originalPath`、`quarantinedPath`、`threatName`（ClamAV が報告した脅威名）、`quarantinedAt: String`（ISO 8601）、`fileSize: Int64`。

### `AppHelpResult`

| フィールド | 型 | 説明 |
|---|---|---|
| `query` | `String?` | 指定したクエリ（そのまま返却） |
| `topic` | `String?` | 指定したトピック（そのまま返却） |
| `totalResults` | `Int` | `items.count` |
| `items` | `[KnowledgeItem]` | 該当エントリ（関連度の高い順） |
| `language` | `String?` | 内容の言語（例: `"ja"`）。古いアプリでは `nil` |

`KnowledgeItem`: `id`、`topic`（`"feature"` / `"alert_message"` / `"setting"` / `"troubleshooting"`）、`title`、`summary`、`details`、`recommendation: String?`、`tags: [String]`。

`AppHelpTopic`: `.all`、`.feature`、`.alertMessage`（`"alert_message"`）、`.setting`、`.troubleshooting`。

### `IncidentTimeline`

| フィールド | 型 | 説明 |
|---|---|---|
| `unresolvedCount` | `Int` | `events` のうち `status` が `"open"` の件数 |
| `events` | `[IncidentTimelineEvent]` | 新しい順 |
| `caveats` | `[String]` | 注記（例: `summary` は検知時点の表示言語で記録される） |

`IncidentTimelineEvent`: `id`、`timestamp: String`（ISO 8601）、`source`（`"arpSpoof"` / `"ransomwareCanary"` / `"runtimeThreat"` / `"portAnomaly"`）、`sourceLabel`（ローカライズ済み）、`severity`、`summary`、`processName: String?`、`processID: Int32?`、`attackTechnique: String?`（確度の高い場合のみの MITRE ATT&CK ID）、`actionTaken`（`"air_gap"` / `"port_block"` など）、`actionTakenLabel`（ローカライズ済み）、`status`（`"open"` / `"released"` / `"autoTimeout"` / `"allowlisted"`）、`resolvedAt: String?`（ISO 8601）。

### `NetworkHistory`

| フィールド | 型 | 説明 |
|---|---|---|
| `knownNetworkCount` | `Int` | 記憶している全 SSID 数（`limit` の影響を受けない） |
| `networks` | `[KnownNetwork]` | 最終接続が新しい順。`limit` 件まで |
| `lookalikePairs` | `[LookalikeNetworkPair]` | 常に全件 |
| `caveats` | `[String]` | 返す内容・返さない内容の注記 |

`KnownNetwork`: `ssid`、`gatewayCount: Int`（応答したゲートウェイ機器の数。MAC アドレスは返しません）、`lastSeen: String`（ISO 8601）。

`LookalikeNetworkPair`: `ssid`、`similarTo`、`editDistance: Int` — 名前が酷似しているのに一度も同じゲートウェイ機器を共有していない SSID の組（過去の Evil Twin 候補）。

### `DocResource` / `DocResourceContent`

`DocResource`: `uri`（例: `roamswitch://docs/features`）、`name`、`description`、`mimeType`。

`DocResourceContent`: `uri`、`mimeType`（`"text/markdown"`）、`text`。

### `RoamSwitchClientError`

| ケース | 意味 |
|---|---|
| `.appNotInstalled` | 指定バンドル ID のアプリが Launch Services に登録されていない |
| `.serverBinaryNotFound` | RoamSwitch はあるが 1.3.0 より前（バンドル内に `RoamSwitchMCPServer` が無い） |
| `.processLaunchFailed(underlying:)` | サブプロセスの起動自体に失敗した |
| `.noResponse` | レスポンスが届く前にサブプロセスの stdout が閉じた |
| `.timedOut` | `timeout` 内に応答が無く、サブプロセスを終了させた |
| `.invalidResponse(raw:)` | 応答はあったが、正しい／想定どおりの JSON-RPC ではなかった |
| `.toolError(message:)` | サーバーが JSON-RPC エラー、または `isError: true` のツール結果を返した（インストール済み RoamSwitch がそのメソッドより古い場合の "Unknown tool" を含む。上のバージョン表を参照） |

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
