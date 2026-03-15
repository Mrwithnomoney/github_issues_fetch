#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import List, Optional, Tuple

import argparse
import datetime
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

BASE_URL = "https://api.github.com/search/issues"
OPENAI_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_DAYS = 7
DEFAULT_MAX = 20
MAX_PER_PAGE = 100
MAX_PAGES = 10  # GitHub Search API 1000 results limit
SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

TYPE_MAP = {
    "rce": {
        "name": "RCE",
        "keywords": '"remote code exec" OR "remote code execution" OR RCE OR "command execution"',
        "tags": ["#安全", "#漏洞复现", "#RCE", "#命令执行"],
    },
    "sqli": {
        "name": "SQL注入",
        "keywords": '"sql injection" OR "sql inject" OR SQLi',
        "tags": ["#安全", "#漏洞复现", "#SQL注入"],
    },
    "arbitrary-file": {
        "name": "任意文件",
        "keywords": '"arbitrary file" OR "file read" OR "path traversal" OR "directory traversal" OR "file upload"',
        "tags": ["#安全", "#漏洞复现", "#文件上传", "#文件包含", "#信息泄露"],
    },
    "deserialization": {
        "name": "反序列化",
        "keywords": '"deserialization" OR "unsafe deserialize" OR "insecure deserialization" OR "unsafe deserialization"',
        "tags": ["#安全", "#漏洞复现", "#反序列化"],
    },
}


def build_query(keywords: str, days: int) -> str:
    parts = ["is:issue", f"({keywords})"]
    if days and days > 0:
        since = (datetime.datetime.utcnow() - datetime.timedelta(days=days)).strftime("%Y-%m-%d")
        parts.append(f"updated:>={since}")
    return " ".join(parts)


def request_json(url: str, token: Optional[str], retries: int = 3) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "github-issues-vuln-tracker",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = resp.read().decode("utf-8")
                return json.loads(data)
        except urllib.error.HTTPError as e:
            status = e.code
            body = e.read().decode("utf-8") if e.fp else ""
            if status in (401, 403):
                raise RuntimeError(f"HTTP {status}: 认证失败或触发限速。响应：{body}")
            raise RuntimeError(f"HTTP {status}: {body}")
        except urllib.error.URLError as e:
            if attempt == retries:
                raise RuntimeError(f"网络错误：{e}")
            time.sleep(1 * attempt)

    raise RuntimeError("未知错误")


def summarize(text: str, limit: int = 200) -> str:
    if not text:
        return ""
    clean = " ".join(text.replace("\r", " ").replace("\n", " ").split())
    if len(clean) <= limit:
        return clean
    return clean[:limit].rstrip() + "..."


def spinner_task(stop_event: threading.Event, label: str = "AI 筛选中") -> None:
    idx = 0
    while not stop_event.is_set():
        frame = SPINNER_FRAMES[idx % len(SPINNER_FRAMES)]
        print(f"\r{frame} {label}...", file=sys.stderr, end="", flush=True)
        idx += 1
        time.sleep(0.1)
    print("\r✓ AI 筛选完成" + " " * 30, file=sys.stderr, flush=True)


def truncate_text(text: str, limit: int = 60) -> str:
    if not text:
        return ""
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def format_issue_table(
    title: str,
    url: str,
    repo: str,
    updated: str,
    labels: str,
    summary: str,
    extra_rows: Optional[List[Tuple[str, str]]] = None,
) -> list[str]:
    rows = []
    rows.append("| 字段 | 内容 |")
    rows.append("| --- | --- |")
    rows.append(f"| 链接 | [{url}]({url}) |")
    rows.append(f"| 仓库 | {repo} |")
    rows.append(f"| 更新时间 | {updated} |")
    rows.append(f"| Labels | {labels} |")
    if extra_rows:
        for key, value in extra_rows:
            rows.append(f"| {key} | {value} |")

    lines = [f"### {title}", ""] + rows
    if summary:
        lines.append("")
        lines.append("**摘要**")
        lines.append(f"> {summary}")
    lines.append("")
    return lines


def format_markdown(items: list[dict], meta: dict) -> str:
    lines: list[str] = []
    lines.append(" ".join(meta["tags"]))
    lines.append("")
    lines.append("## 检索条件")
    lines.append(f"- 类型：{meta['type_name']}")
    lines.append(f"- 关键词：{meta['keywords']}")
    lines.append(f"- 更新范围：{meta['days_desc']}")
    lines.append(f"- 最大条数：{meta['max_items']}")
    lines.append(f"- 生成时间：{meta['generated_at']}")
    lines.append("")
    lines.append("## 统计")
    lines.append(f"- 实际条数：{len(items)}")
    lines.append("")
    lines.append(f"## 结果（{len(items)}）")

    if not items:
        lines.append("未检索到结果。")
        return "\n".join(lines) + "\n"

    for idx, item in enumerate(items, start=1):
        title = (item.get("title") or "").strip()
        url = item.get("html_url") or ""
        updated = (item.get("updated_at") or "")[:10]
        repo_api = item.get("repository_url") or ""
        repo_name = repo_api.replace("https://api.github.com/repos/", "") if repo_api else "未知仓库"
        labels = [lbl.get("name") for lbl in item.get("labels", []) if lbl.get("name")]
        label_text = ", ".join(labels) if labels else "无"
        summary = summarize(item.get("body") or "")

        lines.extend(
            format_issue_table(
                title=f"{idx}. {title}",
                url=url,
                repo=repo_name,
                updated=updated,
                labels=label_text,
                summary=summary,
            )
        )

    return "\n".join(lines) + "\n"


def read_token_from_file(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            token = f.read().strip()
            return token if token else None
    except FileNotFoundError:
        return None


def read_config(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as e:
        raise RuntimeError(f"配置文件解析失败：{e}")


def build_issue_brief(item: dict) -> dict:
    repo_api = item.get("repository_url") or ""
    repo_name = repo_api.replace("https://api.github.com/repos/", "") if repo_api else "未知仓库"
    labels = [lbl.get("name") for lbl in item.get("labels", []) if lbl.get("name")]
    return {
        "title": (item.get("title") or "").strip(),
        "url": item.get("html_url") or "",
        "repo": repo_name,
        "labels": labels,
        "updated_at": (item.get("updated_at") or "")[:10],
        "summary": summarize(item.get("body") or ""),
    }


def build_filter_prompt(issue: dict) -> str:
    labels = ", ".join(issue.get("labels") or []) or "无"
    return (
        "你是一名安全研究员，请判断以下 GitHub Issue 是否与安全漏洞/安全缺陷相关。\n"
        "仅输出 JSON，不要包含多余文本。\n\n"
        "判断标准：\n"
        "- relevant=true：明显涉及安全漏洞、可被利用的安全缺陷、权限绕过、信息泄露、RCE、SQL 注入、反序列化等。\n"
        "- relevant=false：普通 bug、功能需求、性能问题、使用问题、非安全缺陷。\n\n"
        "输出 JSON 格式：\n"
        "{\"relevant\": true/false, \"confidence\": \"low\"|\"med\"|\"high\", \"reason\": \"一句话理由\"}\n\n"
        "Issue 信息：\n"
        f"标题：{issue.get('title', '')}\n"
        f"仓库：{issue.get('repo', '')}\n"
        f"标签：{labels}\n"
        f"更新时间：{issue.get('updated_at', '')}\n"
        f"摘要：{issue.get('summary', '')}\n"
    )


def request_openai_filter(
    issue: dict,
    api_key: str,
    model: str,
    base_url: str,
    retries: int = 3,
) -> dict:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    payload = {
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": "You are a precise security analyst."},
            {"role": "user", "content": build_filter_prompt(issue)},
        ],
    }

    for attempt in range(1, retries + 1):
        req = urllib.request.Request(
            base_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read().decode("utf-8")
                parsed = json.loads(data)
                content = (
                    parsed.get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", "")
                    .strip()
                )
                return json.loads(content)
        except urllib.error.HTTPError as e:
            status = e.code
            body = e.read().decode("utf-8") if e.fp else ""
            if status in (401, 403):
                raise RuntimeError(f"OpenAI HTTP {status}: 认证失败或权限不足。响应：{body}")
            if status == 429:
                if attempt == retries:
                    raise RuntimeError(f"OpenAI HTTP 429: 触发限速。响应：{body}")
                time.sleep(1 * attempt)
                continue
            raise RuntimeError(f"OpenAI HTTP {status}: {body}")
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            if attempt == retries:
                raise RuntimeError(f"OpenAI 请求失败：{e}")
            time.sleep(1 * attempt)

    raise RuntimeError("OpenAI 请求失败：未知错误")


def format_filtered_markdown(items: list[dict], meta: dict) -> str:
    lines: list[str] = []
    lines.append(" ".join(meta["tags"]))
    lines.append("")
    lines.append("## 检索条件")
    lines.append(f"- 类型：{meta['type_name']}")
    lines.append(f"- 关键词：{meta['keywords']}")
    lines.append(f"- 更新范围：{meta['days_desc']}")
    lines.append(f"- 最大条数：{meta['max_items']}")
    lines.append(f"- 生成时间：{meta['generated_at']}")
    lines.append("")
    lines.append("## AI 筛选")
    lines.append(f"- 模型：{meta['filter_model']}")
    lines.append(f"- 实际筛选：{meta['filter_count']}")
    lines.append("")
    lines.append(f"## 结果（{len(items)}）")

    if not items:
        lines.append("未检索到相关漏洞结果。")
        return "\n".join(lines) + "\n"

    for idx, entry in enumerate(items, start=1):
        issue = entry["issue"]
        decision = entry["decision"]
        title = issue.get("title") or ""
        url = issue.get("url") or ""
        repo = issue.get("repo") or ""
        updated = issue.get("updated_at") or ""
        labels = ", ".join(issue.get("labels") or []) or "无"
        summary = issue.get("summary") or ""
        confidence = decision.get("confidence", "")
        reason = decision.get("reason", "")

        extra_rows = [("AI判断", "相关")]
        if confidence:
            extra_rows.append(("置信度", confidence))
        if reason:
            extra_rows.append(("理由", reason))

        lines.extend(
            format_issue_table(
                title=f"{idx}. {title}",
                url=url,
                repo=repo,
                updated=updated,
                labels=labels,
                summary=summary,
                extra_rows=extra_rows,
            )
        )

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="GitHub issues 漏洞检索（按类型输出 Obsidian 笔记）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "  python3 github_issues_fetch.py --type rce\n"
            "  python3 github_issues_fetch.py --type sqli --days 14 --max 30\n"
            "  python3 github_issues_fetch.py --type privesc --days 0\n"
            "  python3 github_issues_fetch.py --type rce --filter\n"
            "  python3 github_issues_fetch.py --type rce --filter --config github_issues_config.json\n\n"
            "Token：\n"
            "  1) 环境变量 GITHUB_TOKEN\n"
            "  2) 同目录 token.txt（仅一行 token）\n"
            "  3) 配置文件 github_issues_config.json 中 github_token\n\n"
            "AI 筛选：\n"
            "  1) --filter 启用筛选\n"
            "  2) 配置文件 github_issues_config.json 中 openai_api_key/openai_base_url/openai_model\n"
        ),
    )
    parser.add_argument("--type", required=True, choices=TYPE_MAP.keys(), help="漏洞类型")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS, help="更新范围（天），0 表示不限")
    parser.add_argument("--max", dest="max_items", type=int, default=DEFAULT_MAX, help="最大条数")
    parser.add_argument(
        "--filter",
        action="store_true",
        help="启用 AI 相关性筛选并生成筛选后笔记",
    )
    parser.add_argument(
        "--filter-output",
        default="",
        help="筛选后笔记输出路径（默认在同目录生成 -filtered 文件）",
    )
    parser.add_argument(
        "--config",
        default="github_issues_config.json",
        help="配置文件（默认同目录 github_issues_config.json）",
    )
    parser.add_argument(
        "--model",
        default="gpt-4.1-mini",
        help="OpenAI 模型名（默认 gpt-4.1-mini）",
    )
    parser.add_argument(
        "--max-filter",
        type=int,
        default=0,
        help="最多筛选条数（默认等于 --max）",
    )
    parser.add_argument(
        "--output-dir",
        default="result",
        help="输出目录（默认 result）",
    )

    args = parser.parse_args()
    if args.max_items <= 0:
        print("--max 必须大于 0", file=sys.stderr)
        return 1

    type_cfg = TYPE_MAP[args.type]
    query = build_query(type_cfg["keywords"], args.days)

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        token_path = os.path.join(os.path.dirname(__file__), "token.txt")
        token = read_token_from_file(token_path)

    config_path = args.config
    if not os.path.isabs(config_path):
        config_path = os.path.join(os.path.dirname(__file__), config_path)
    config = read_config(config_path) if args.config else {}

    if not token:
        token = (config.get("github_token") or "").strip() or None

    if not token:
        print("未检测到 GITHUB_TOKEN、token.txt 或配置文件 github_token，将以匿名模式请求，可能触发限速。", file=sys.stderr)

    api_key = (config.get("openai_api_key") or "").strip()
    api_base_url = (config.get("openai_base_url") or "").strip() or OPENAI_URL
    model = (config.get("openai_model") or "").strip() or args.model

    if args.filter and not api_key:
        print("启用 --filter 但未提供 API Key，请在配置文件中设置 openai_api_key。", file=sys.stderr)
        return 1

    items: list[dict] = []
    page = 1
    while len(items) < args.max_items and page <= MAX_PAGES:
        per_page = min(MAX_PER_PAGE, args.max_items - len(items))
        params = {
            "q": query,
            "sort": "updated",
            "order": "desc",
            "per_page": per_page,
            "page": page,
        }
        url = f"{BASE_URL}?{urllib.parse.urlencode(params)}"
        data = request_json(url, token)
        page_items = data.get("items", [])
        if not page_items:
            break
        items.extend(page_items)
        page += 1

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    days_desc = "不限" if args.days == 0 else f"最近{args.days}天"
    meta = {
        "tags": type_cfg["tags"],
        "type_name": type_cfg["name"],
        "keywords": type_cfg["keywords"],
        "days_desc": days_desc,
        "max_items": args.max_items,
        "generated_at": now,
    }

    content = format_markdown(items[: args.max_items], meta)

    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    filename = f"GitHub-Issues-{args.type}-{timestamp}.md"
    output_path = os.path.join(args.output_dir, filename)

    os.makedirs(args.output_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"已生成：{output_path}")
    print(f"结果已输出到目录：{args.output_dir}")

    if args.filter:
        max_filter = args.max_filter if args.max_filter > 0 else args.max_items
        briefs = [build_issue_brief(item) for item in items[:max_filter]]
        filtered: list[dict] = []
        stop_event = threading.Event()
        spinner = threading.Thread(target=spinner_task, args=(stop_event,), daemon=True)
        spinner.start()

        try:
            for idx, brief in enumerate(briefs, start=1):
                title = truncate_text(brief.get("title", ""), 50)
                print(f"\n处理 {idx}/{len(briefs)}: {title}", file=sys.stderr, flush=True)
                decision = request_openai_filter(
                    brief,
                    api_key=api_key,
                    model=model,
                    base_url=api_base_url,
                )
                if decision.get("relevant") is True:
                    filtered.append({"issue": brief, "decision": decision})
        finally:
            stop_event.set()
            spinner.join()

        filtered_meta = {
            **meta,
            "filter_model": model,
            "filter_count": len(briefs),
        }
        filtered_content = format_filtered_markdown(filtered, filtered_meta)

        if args.filter_output:
            filtered_path = args.filter_output
            if not os.path.isabs(filtered_path):
                filtered_path = os.path.join(args.output_dir, filtered_path)
        else:
            base_name = os.path.splitext(filename)[0]
            filtered_path = os.path.join(args.output_dir, f"{base_name}-filtered.md")

        with open(filtered_path, "w", encoding="utf-8") as f:
            f.write(filtered_content)

        print(f"已生成筛选结果：{filtered_path}")
        print(f"筛选结果已输出到目录：{args.output_dir}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
