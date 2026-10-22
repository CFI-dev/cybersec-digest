#!/usr/bin/env python3
"""
cybersec-digest — 最小構成のサイバーセキュリティ情報アグリゲーター

処理:
  1. CISA KEV(実際に悪用が確認された脆弱性)の JSON を取得
  2. config/feeds.json に定義した RSS/Atom フィード群を取得
  3. data/ に保存した前回スナップショットと差分を取り「新着」だけを抽出
  4. 静的な HTML ダッシュボード(docs/index.html)を生成
  5. SLACK_WEBHOOK_URL があれば Slack に新着を通知

環境変数:
  SLACK_WEBHOOK_URL : Slack Incoming Webhook URL(未設定なら通知をスキップ)
  DIGEST_TZ_OFFSET  : 表示タイムゾーンの UTC オフセット(既定 9 = JST)
  DIGEST_NO_SLACK   : "1" を指定すると通知を強制スキップ(ローカル検証用)
"""
from __future__ import annotations

import html
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import feedparser
import requests

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "feeds.json"
DATA_DIR = ROOT / "data"
DOCS_DIR = ROOT / "docs"
TEMPLATE_PATH = ROOT / "templates" / "index.template.html"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CSV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

KEV_SNAPSHOT = DATA_DIR / "kev_snapshot.json"
SEEN_ITEMS = DATA_DIR / "seen_items.json"
HISTORY = DATA_DIR / "history.json"

SEEN_LIMIT = 5000      # 既読アイテム ID の保持上限
HISTORY_LIMIT = 300    # ダッシュボードに残す新着履歴の上限

TZ_OFFSET = int(os.environ.get("DIGEST_TZ_OFFSET", "9"))
TZ = timezone(timedelta(hours=TZ_OFFSET))
TZ_LABEL = f"UTC{'+' if TZ_OFFSET >= 0 else ''}{TZ_OFFSET}"

HEADERS = {"User-Agent": "cybersec-digest/1.0 (+https://github.com/)"}
TIMEOUT = 30


# ---------------------------------------------------------------- utilities
def load_json(path: Path, default):
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")


def now() -> datetime:
    return datetime.now(TZ)


def iso(dt: datetime) -> str:
    return dt.astimezone(TZ).strftime("%Y-%m-%d %H:%M %Z")


def esc(text) -> str:
    return html.escape(str(text or ""), quote=True)


def dt_from_struct(struct_time) -> datetime | None:
    if not struct_time:
        return None
    try:
        return datetime(*struct_time[:6], tzinfo=timezone.utc).astimezone(TZ)
    except (ValueError, TypeError):
        return None


def time_ago(dt: datetime | None) -> str:
    if dt is None:
        return "—"
    delta = now() - dt
    secs = int(delta.total_seconds())
    if secs < 0:
        secs = 0
    if secs < 3600:
        return f"{secs // 60} 分前"
    if secs < 86400:
        return f"{secs // 3600} 時間前"
    return f"{secs // 86400} 日前"


# ---------------------------------------------------------------- fetch KEV
def fetch_kev():
    """KEV カタログを取得し (entries, total) を返す。失敗時は例外。"""
    resp = requests.get(KEV_URL, headers=HEADERS, timeout=TIMEOUT)
    resp.raise_for_status()
    catalog = resp.json()
    entries = catalog.get("vulnerabilities", [])
    return entries, catalog.get("count", len(entries))


# ---------------------------------------------------------------- fetch RSS
def fetch_feeds(feeds):
    """各フィードを取得し (items, statuses) を返す。"""
    items, statuses = [], []
    for feed in feeds:
        name = feed.get("name", feed.get("url", "?"))
        url = feed["url"]
        category = feed.get("category", "news")
        lang = feed.get("lang", "en")
        try:
            parsed = feedparser.parse(url, agent=HEADERS["User-Agent"], request_headers=HEADERS)
            if getattr(parsed, "bozo", 0) and not parsed.entries:
                raise RuntimeError(getattr(parsed, "bozo_exception", "parse error"))
            count = 0
            for entry in parsed.entries:
                ident = entry.get("id") or entry.get("link") or entry.get("title")
                if not ident:
                    continue
                published = (
                    dt_from_struct(entry.get("published_parsed"))
                    or dt_from_struct(entry.get("updated_parsed"))
                )
                items.append(
                    {
                        "source": name,
                        "category": category,
                        "lang": lang,
                        "id": str(ident),
                        "title": (entry.get("title") or "(無題)").strip(),
                        "link": entry.get("link", ""),
                        "published": iso(published) if published else "",
                        "published_ts": published.timestamp() if published else 0,
                    }
                )
                count += 1
            statuses.append({"name": name, "url": url, "ok": True, "count": count})
        except Exception as exc:  # noqa: BLE001 — フィード単位で失敗を握る
            statuses.append(
                {"name": name, "url": url, "ok": False, "count": 0, "error": str(exc)[:160]}
            )
    return items, statuses


# ---------------------------------------------------------------- classify
RANSOM_MARK = "Known"


def kev_priority(entry) -> str:
    """KEV エントリの優先度ラベルを返す。"""
    return "critical" if entry.get("knownRansomwareCampaignUse") == RANSOM_MARK else "kev"


CATEGORY_LABEL = {
    "advisory": "注意喚起",
    "vuln": "脆弱性",
    "breach": "情報漏洩",
    "news": "ニュース",
    "kev": "KEV",
}


def category_label(cat: str) -> str:
    return CATEGORY_LABEL.get(cat, cat)


# ---------------------------------------------------------------- render HTML
def render_kev_band(records) -> str:
    label = '<span class="kev-band__label">KEV 新規</span>'
    if not records:
        return label + '<span class="kev-band__empty">今回の新規追加はありません。</span>'
    chips = []
    for r in records:
        rm = '<span class="kev-chip__rm">ランサム</span>' if r.get("priority") == "critical" else ""
        chips.append(
            '<a class="kev-chip" href="' + esc(r.get("link", "")) + '" target="_blank" rel="noopener">'
            '<span class="kev-chip__cve">' + esc(r.get("cve", "")) + '</span>'
            '<span class="kev-chip__prod">' + esc(r.get("product", "")) + '</span>' + rm + '</a>'
        )
    return label + "".join(chips)


def render_timeline(records, empty_msg="今回の新着はありません。") -> str:
    if not records:
        return '<p class="empty">' + empty_msg + '</p>' 
    rows = []
    for rec in records:
        kind = rec.get("kind", "news")
        rail = "is-critical" if rec.get("priority") == "critical" else (
            "is-kev" if kind == "kev" else "is-news"
        )
        src = esc(rec.get("source", ""))
        title = esc(rec.get("title", ""))
        link = esc(rec.get("link", ""))
        tag = esc(category_label(rec.get("category", "news")))
        when = esc(rec.get("published") or rec.get("detected", ""))
        badge = '<span class="badge badge--new">NEW</span>' if rec.get("is_new") else ""
        ransom = (
            '<span class="badge badge--ransom">ランサムウェアで悪用</span>'
            if rec.get("priority") == "critical"
            else ""
        )
        if kind == "kev":
            meta = f'{esc(rec.get("cve", ""))} ・ {esc(rec.get("product", ""))}'
            body = f'<p class="item-desc">{esc(rec.get("desc", ""))}</p>'
            head = f'<span class="item-title item-title--kev">{title}</span>'
        else:
            meta = f"{when} ・ {tag}"
            body = ""
            head = (
                f'<a class="item-title" href="{link}" target="_blank" rel="noopener">{title}</a>'
                if link
                else f'<span class="item-title">{title}</span>'
            )
        rows.append(
            f"""<article class="item {rail}">
  <div class="item-rail" aria-hidden="true"></div>
  <div class="item-body">
    <div class="item-meta">
      <span class="chip">{src}</span>{badge}{ransom}
      <span class="item-time" title="{esc(rec.get('detected', ''))}">{meta}</span>
    </div>
    {head}
    {body}
  </div>
</article>"""
        )
    return "\n".join(rows)


def render_ja_list(records) -> str:
    if not records:
        return '<p class="empty">国内フィードの取得結果がありません。</p>'
    rows = []
    for i in records:
        title = esc(i.get("title", ""))
        link = esc(i.get("link", ""))
        src = esc(i.get("source", ""))
        when = esc(i.get("published", ""))
        if link:
            head = '<a class="item-title" href="' + link + '" target="_blank" rel="noopener">' + title + '</a>'
        else:
            head = '<span class="item-title">' + title + '</span>'
        rows.append(
            '<article class="item is-news"><div class="item-rail" aria-hidden="true"></div>'
            '<div class="item-body"><div class="item-meta"><span class="chip">' + src + '</span>'
            '<span class="badge badge--dom">国内</span>'
            '<span class="item-time">' + when + '</span></div>' + head + '</div></article>'
        )
    return "\n".join(rows)


def render_kev_rows(entries) -> str:
    rows = []
    for e in entries[:25]:
        ransom = e.get("knownRansomwareCampaignUse") == RANSOM_MARK
        flag = '<span class="flag flag--on">Known</span>' if ransom else '<span class="flag">Unknown</span>'
        cve = e.get("cveID", "")
        rows.append(
            f"""<tr>
  <td class="mono"><a href="https://www.cve.org/CVERecord?id={esc(cve)}" target="_blank" rel="noopener">{esc(cve)}</a></td>
  <td>{esc(e.get('dateAdded', ''))}</td>
  <td>{esc(e.get('vendorProject', ''))} / {esc(e.get('product', ''))}</td>
  <td>{flag}</td>
</tr>"""
        )
    return "\n".join(rows) if rows else '<tr><td colspan="4">データなし</td></tr>'


def render_feed_rows(statuses) -> str:
    rows = []
    for s in statuses:
        dot = "ok" if s.get("ok") else "fail"
        note = f"{s.get('count', 0)} 件" if s.get("ok") else esc(s.get("error", "取得失敗"))
        rows.append(
            f'<li class="feed-row"><span class="dot dot--{dot}" aria-hidden="true"></span>'
            f'<span class="feed-name">{esc(s.get("name", ""))}</span>'
            f'<span class="feed-note">{note}</span></li>'
        )
    return "\n".join(rows)


def build_html(context: dict) -> str:
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    for key, value in context.items():
        template = template.replace("{{" + key + "}}", str(value))
    return template


# ---------------------------------------------------------------- Slack
def notify_slack(new_kev, new_news) -> None:
    if os.environ.get("DIGEST_NO_SLACK") == "1":
        print("Slack 通知は DIGEST_NO_SLACK=1 のためスキップ")
        return
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook:
        print("SLACK_WEBHOOK_URL 未設定のため通知をスキップ")
        return
    if not new_kev and not new_news:
        print("新着がないため Slack 通知をスキップ")
        return

    lines = [":rotating_light: *サイバーセキュリティ ダイジェスト — 新着*"]
    if new_kev:
        lines.append(f"\n*CISA KEV(悪用確認済み) 新規 {len(new_kev)} 件*")
        for e in new_kev[:10]:
            flag = " :fire: ランサムウェア" if e.get("knownRansomwareCampaignUse") == RANSOM_MARK else ""
            lines.append(
                f"• <https://www.cve.org/CVERecord?id={e.get('cveID','')}|{e.get('cveID','')}> "
                f"{e.get('vendorProject','')} {e.get('product','')}{flag}"
            )
    if new_news:
        lines.append(f"\n*ニュース/注意喚起 新規 {len(new_news)} 件(抜粋)*")
        for it in new_news[:8]:
            link = it.get("link") or ""
            title = it.get("title", "")
            if link:
                lines.append(f"• <{link}|{title}> — {it.get('source','')}")
            else:
                lines.append(f"• {title} — {it.get('source','')}")

    payload = {"text": "\n".join(lines), "unfurl_links": False}
    resp = requests.post(webhook, json=payload, timeout=TIMEOUT)
    resp.raise_for_status()
    print(f"Slack 通知を送信しました (status={resp.status_code})")


# ---------------------------------------------------------------- main
def main() -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DOCS_DIR.mkdir(parents=True, exist_ok=True)

    config = load_json(CONFIG_PATH, {"feeds": []})
    feeds = config.get("feeds", [])

    kev_prev = load_json(KEV_SNAPSHOT, {"cve_ids": []})
    seen_prev = load_json(SEEN_ITEMS, {"ids": []})
    history = load_json(HISTORY, {"entries": []})

    first_run = not KEV_SNAPSHOT.exists() and not SEEN_ITEMS.exists()
    prev_kev_ids = set(kev_prev.get("cve_ids", []))
    prev_seen = set(seen_prev.get("ids", []))

    # --- KEV ---------------------------------------------------------------
    kev_entries, kev_total = fetch_kev()
    current_kev_ids = {e.get("cveID", "") for e in kev_entries}
    if first_run:
        new_kev = []
    else:
        new_kev = [e for e in kev_entries if e.get("cveID") and e.get("cveID") not in prev_kev_ids]
    new_kev.sort(key=lambda e: e.get("dateAdded", ""), reverse=True)

    # --- feeds -------------------------------------------------------------
    feed_items, feed_statuses = fetch_feeds(feeds)
    if first_run:
        new_news = []
    else:
        new_news = [i for i in feed_items if i["id"] not in prev_seen]
    new_news.sort(key=lambda i: i.get("published_ts", 0), reverse=True)
    MAX_PER_COL = 40
    ja_news = [i for i in new_news if i.get("lang") == "ja"]
    ov_news = [i for i in new_news if i.get("lang") != "ja"]
    ja_extra = max(0, len(ja_news) - MAX_PER_COL)
    ov_extra = max(0, len(ov_news) - MAX_PER_COL)
    new_news = ja_news[:MAX_PER_COL] + ov_news[:MAX_PER_COL]

    # --- merge for timeline ------------------------------------------------
    detected = iso(now())
    fresh = []
    for e in new_kev:
        fresh.append(
            {
                "kind": "kev",
                "source": "CISA KEV",
                "category": "kev",
                "priority": "critical" if e.get("knownRansomwareCampaignUse") == RANSOM_MARK else "kev",
                "cve": e.get("cveID", ""),
                "product": f"{e.get('vendorProject','')} {e.get('product','')}".strip(),
                "title": e.get("vulnerabilityName") or e.get("cveID", ""),
                "link": f"https://www.cve.org/CVERecord?id={e.get('cveID','')}",
                "desc": e.get("shortDescription", ""),
                "published": e.get("dateAdded", ""),
                "detected": detected,
                "is_new": True,
            }
        )
    for i in new_news:
        fresh.append(
            {
                "kind": "news",
                "source": i["source"],
                "category": i["category"],
                "lang": i.get("lang", "en"),
                "priority": "news",
                "title": i["title"],
                "link": i["link"],
                "published": i["published"],
                "detected": detected,
                "is_new": True,
            }
        )

    # 履歴を更新(今回の新着を先頭に追加、上限でトリム)
    history_entries = [dict(x, is_new=False) for x in history.get("entries", [])]
    merged = fresh + history_entries
    merged = merged[:HISTORY_LIMIT]

    # --- 永続化 ------------------------------------------------------------
    save_json(KEV_SNAPSHOT, {"updated": detected, "count": len(current_kev_ids), "cve_ids": sorted(current_kev_ids)})

    ids = list(prev_seen) + [i["id"] for i in feed_items]
    # 重複排除しつつ上限まで
    deduped = list(dict.fromkeys(ids))
    save_json(SEEN_ITEMS, {"updated": detected, "ids": deduped[-SEEN_LIMIT:]})
    save_json(HISTORY, {"updated": detected, "entries": merged})

    # --- HTML --------------------------------------------------------------
    ja_items = sorted(
        [i for i in feed_items if i.get("lang") == "ja"],
        key=lambda i: i.get("published_ts", 0),
        reverse=True,
    )[:20]
    latest_kev = sorted(kev_entries, key=lambda e: e.get("dateAdded", ""), reverse=True)
    fresh_kev = [x for x in fresh if x.get("kind") == "kev"]
    fresh_news = [x for x in fresh if x.get("kind") != "kev"]
    fresh_ja = [x for x in fresh_news if x.get("lang") == "ja"]
    fresh_ov = [x for x in fresh_news if x.get("lang") != "ja"]
    kev_band_html = render_kev_band(fresh_kev)
    ja_new_html = render_timeline(fresh_ja, "国内の新着はありません。")
    if ja_extra:
        ja_new_html += '\n<p class="empty">ほか ' + str(ja_extra) + ' 件（国内）</p>'
    ov_new_html = render_timeline(fresh_ov, "海外の新着はありません。")
    if ov_extra:
        ov_new_html += '\n<p class="empty">ほか ' + str(ov_extra) + ' 件（海外）</p>'

    context = {
        "GENERATED_AT": detected,
        "MODE_NOTE": "初回実行(ベースライン記録。今回の新着通知は行いません)" if first_run else "定期更新",
        "KEV_NEW_COUNT": len(new_kev),
        "NEW_COUNT": len(new_news),
        "FEEDS_OK": sum(1 for s in feed_statuses if s.get("ok")),
        "FEEDS_TOTAL": len(feed_statuses),
        "KEV_TOTAL": f"{kev_total:,}",
        "KEV_BAND_HTML": kev_band_html,
        "JA_NEW_HTML": ja_new_html,
        "OV_NEW_HTML": ov_new_html,
        "JA_NEW_COUNT": len(fresh_ja),
        "OV_NEW_COUNT": len(fresh_ov),
        "JA_ITEMS_HTML": render_ja_list(ja_items),
        "JA_COUNT": len(ja_items),
        "KEV_ROWS_HTML": render_kev_rows(latest_kev),
        "FEED_ROWS_HTML": render_feed_rows(feed_statuses),
        "TZ_LABEL": TZ_LABEL,
    }
    (DOCS_DIR / "index.html").write_text(build_html(context), encoding="utf-8")
    print(f"docs/index.html を生成しました (KEV新規 {len(new_kev)} / ニュース新規 {len(new_news)})")

    # --- Slack -------------------------------------------------------------
    notify_slack(new_kev, new_news)
    return 0


if __name__ == "__main__":
    sys.exit(main())
