# GitHub Issues 漏洞检索小工具

基于 GitHub Search API 按漏洞类型检索 Issue，输出 Obsidian 可用的 Markdown 笔记，可选用 OpenAI 接口做相关性筛选。

## 功能

- 按漏洞类型（RCE/SQLi/任意文件/反序列化）检索最近更新的 GitHub Issues
- 输出包含标签、检索条件、统计信息与结果表格的 Markdown
- 可选 AI 筛选（OpenAI 兼容接口）
- 支持匿名/Token 访问 GitHub API

## 依赖

- Python 3.10+（标准库即可）
- 可选：OpenAI 兼容 API（用于 `--filter`）

## 使用

### 基本用法

```bash
python3 github_issues_fetch.py --type rce
python3 github_issues_fetch.py --type sqli --days 14 --max 30
python3 github_issues_fetch.py --type arbitrary-file --days 0
```

### 启用 AI 筛选

```bash
python3 github_issues_fetch.py --type rce --filter
python3 github_issues_fetch.py --type rce --filter --config github_issues_config.json
```

### 输出路径

```bash
python3 github_issues_fetch.py --type rce --output-dir result
python3 github_issues_fetch.py --type rce --filter-output custom-filtered.md
```

## 参数说明

- `--type`：漏洞类型（必填）
  - `rce` / `sqli` / `arbitrary-file` / `deserialization`
- `--days`：更新范围（天），0 表示不限（默认 7）
- `--max`：最大条数（默认 20）
- `--output-dir`：输出目录（默认 `result`）
- `--filter`：启用 AI 相关性筛选并生成筛选后笔记
- `--filter-output`：筛选后笔记输出路径（默认在输出目录生成 `-filtered` 文件）
- `--config`：配置文件路径（默认同目录 `github_issues_config.json`）
- `--model`：OpenAI 模型名（默认 `gpt-4.1-mini`）
- `--max-filter`：最多筛选条数（默认等于 `--max`）

## GitHub Token 配置

按优先级读取：

1. 环境变量 `GITHUB_TOKEN`
2. 同目录 `token.txt`（仅一行 token）
3. 配置文件 `github_issues_config.json` 的 `github_token`

> 未提供 token 会以匿名模式请求，可能触发限速。

## AI 筛选配置（OpenAI 兼容）

在配置文件中设置：

```json
{
  "openai_api_key": "YOUR_KEY",
  "openai_base_url": "https://api.openai.com/v1/chat/completions",
  "openai_model": "gpt-4.1-mini"
}
```

## 输出示例

- `result/GitHub-Issues-rce-YYYYMMDD-HHMM.md`
- `result/GitHub-Issues-rce-YYYYMMDD-HHMM-filtered.md`

## 备注

- GitHub Search API 最多返回 1000 条结果（脚本最多翻页 10 页）。
- AI 筛选会逐条调用接口，注意配额与限速。
