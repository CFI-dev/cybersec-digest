# cybersec-digest — 最小構成のサイバーセキュリティ情報アグリゲーター

CISA KEV（実際に悪用が確認された脆弱性）と主要なセキュリティ RSS を **GitHub Actions で毎時取得**し、
前回との **差分（新着）だけ** を静的 HTML にして **GitHub Pages** で公開、**Slack にも通知**する最小テンプレートです。
すべて **GitHub の無料枠（公開リポジトリ）** の範囲で動作し、追加のサーバー費用はかかりません。

---

## 何をしてくれるか

| 機能 | 実装 |
|---|---|
| 悪用確認済み脆弱性の取得 | CISA KEV の公式 JSON（認証不要） |
| ニュース/注意喚起の取得 | `config/feeds.json` に列挙した RSS/Atom（日本語＋海外） |
| 新着の抽出 | 前回スナップショット（`data/`）との差分 |
| 1画面ダッシュボード | `docs/index.html` を生成 |
| 公開 | GitHub Pages（`docs/` フォルダを配信） |
| 通知 | Slack Incoming Webhook（新着がある時だけ送信） |
| 定期実行 | GitHub Actions の cron（毎時 05 分）＋ 手動実行ボタン |

---

## ファイル構成

```
cybersec-digest/
├─ .github/workflows/update.yml   # 毎時実行するワークフロー
├─ scripts/collect.py             # 取得→差分→HTML生成→Slack通知の本体
├─ templates/index.template.html  # ダッシュボードの見た目（CSS込み）
├─ config/feeds.json              # 監視する RSS フィード一覧（ここを編集）
├─ docs/
│   ├─ index.html                 # ← 生成物（GitHub Pages の配信対象）
│   └─ .nojekyll                  # Pages にそのまま配信させるための空ファイル
├─ data/                          # 差分検出用の状態（自動更新・コミットされる）
│   ├─ kev_snapshot.json          # 前回の KEV 一覧
│   ├─ seen_items.json            # 既読 RSS アイテムの ID
│   └─ history.json               # 直近の新着履歴（ダッシュボード表示用）
├─ requirements.txt
└─ README.md
```

---

## セットアップ（約5分）

### 1. リポジトリを作成して push
**公開（public）リポジトリを推奨**します。無料プランでも cron による定期実行と GitHub Pages が使えます
（非公開リポジトリの cron 実行は有料プラン、例：GitHub Pro が必要です）。

```bash
git init
git add .
git commit -m "init: cybersec-digest"
git branch -M master
git remote add origin https://github.com/<あなた>/cybersec-digest.git
git push -u origin master
```

> 本リポジトリは **`master`** を既定ブランチとして運用します（`main` を使う場合は読み替えてください）。
> GitHub 上で既定ブランチを確認・変更するには `Settings` → `General` → `Default branch`。

### 2. GitHub Pages を有効化
`Settings` → `Pages` → **Source: Deploy from a branch** → **Branch: `master` / Folder: `/docs`** → Save。
数分後、`https://<あなた>.github.io/cybersec-digest/` でダッシュボードが公開されます。

### 3. Slack 通知を設定（任意）
1. Slack で **Incoming Webhook** を作成し、URL を取得。
2. リポジトリの `Settings` → `Secrets and variables` → `Actions` → **New repository secret**。
   - Name: `SLACK_WEBHOOK_URL`
   - Value: 取得した Webhook URL
3. 未設定でも動作します（その場合は Slack 通知だけスキップされます）。

### 4. 初回実行（ベースライン作成）
`Actions` タブ → `Update security digest` → **Run workflow**。
**初回は全件を「既読」として記録するだけ**で、通知は行いません（大量通知を防ぐため）。
2回目以降の実行から、本当の新着だけが表示・通知されます。

---

## ローカルで試す

```bash
pip install -r requirements.txt
DIGEST_NO_SLACK=1 python3 scripts/collect.py   # Slack を送らずに実行
# → docs/index.html が生成されます
```

---

## 監視するフィードを増やす / 変える

`config/feeds.json` の配列に追記するだけです。

```json
{ "name": "表示名", "url": "https://example.com/feed", "category": "news" }
```

`category` は表示ラベルに使われます：`advisory`（注意喚起）/ `vuln`（脆弱性）/ `breach`（情報漏洩）/ `news`（ニュース）。

初期同梱（いずれも 2026-10-22 時点で取得確認済み）:
Security NEXT / ScanNetSecurity / JPCERT/CC / IPA 重要なセキュリティ情報 /
The Hacker News / BleepingComputer / Krebs on Security / CISA Advisories / Unit 42 / The Record / SecurityWeek

---

## 仕組み（差分検出）

- **KEV**: 今回の `cveID` 集合 − 前回スナップショットの集合 = 新規。`knownRansomwareCampaignUse` が `Known` のものは赤で強調。
- **RSS**: 各アイテムの安定 ID（`id` → `link` → `title`）が既読集合に無ければ新規。既読集合は 5,000 件まで保持。
- **履歴**: 新着は `data/history.json` に蓄積（最大 300 件）。次回実行時に新着が 0 件でも、直前までの動きが画面に残ります。

---

## コスト

| 項目 | 費用 |
|---|---|
| GitHub Actions（公開リポジトリ） | 無料 |
| GitHub Pages（公開リポジトリ） | 無料 |
| 取得元（CISA / RSS 各社） | 無料 |
| Slack | 無料プランで可 |

**合計: 0 円**（公開リポジトリ運用の場合）。

---

## 注意点・制約

- **非公開リポジトリでは定期実行が有料**になります。無料で回すなら公開リポジトリで運用してください。
- **Actions の cron は遅延**することがあります（混雑時に数分〜十数分）。分単位の即時性は保証されません。
- **RSS は仕様変更・提供終了**がありえます。フィードの `ok/fail` はダッシュボード下部の「ソース状況」で確認できます。
- **公開 API はレート制限**がある場合があります。実行頻度を上げる場合は各提供元の公式ドキュメントで制限を確認してください。
- **一次情報での裏取り**を推奨します（IPA / JPCERT/CC / JVN / NVD / CISA / 各ベンダ）。
- 集約はあくまで補助です。**重要な判断は専門家に確認**してください。

---

## 参考リンク（一次情報）

- CISA KEV カタログ: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA KEV JSON: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- JVN iPedia: https://jvndb.jvn.jp/ ／ JPCERT/CC: https://www.jpcert.or.jp/
- NVD: https://nvd.nist.gov/ ／ EPSS: https://api.first.org/data/1.0/epss
- GitHub Pages: https://docs.github.com/en/pages
- Cloudflare Workers（代替の実行基盤）: https://developers.cloudflare.com/workers/
