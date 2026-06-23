#!/usr/bin/env python3
"""Generate a static MITRE ATT&CK-style TTP overview for GitHub Pages."""

from __future__ import annotations

import argparse
import json
import re
from html import escape
from pathlib import Path


TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Evasion",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Inhibit Response Function",
    "Impair Process Control",
    "Impact",
]


def slugify(value: str) -> str:
    slug = value.lower().replace("&", " and ")
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-")


def html_page(title: str, body: str, depth: int = 0) -> str:
    prefix = "../" * depth
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)} | Dataset TTP Overview</title>
  <link rel="icon" href="{prefix}favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="{prefix}styles.css">
</head>
<body>
{body}
</body>
</html>
"""


def page_header(active: str = "") -> str:
    overview_class = ' class="active"' if active == "overview" else ""
    return f"""  <header class="site-header">
    <a class="brand" href="{'' if active == 'overview' else '../'}index.html">
      <span class="brand-mark">TTP</span>
      <span>
        <strong>Dataset Mapping</strong>
        <small>MITRE ATT&CK overview</small>
      </span>
    </a>
    <nav aria-label="Primary">
      <a{overview_class} href="{'' if active == 'overview' else '../'}index.html">Matrix</a>
    </nav>
  </header>"""


def technique_link(name: str) -> str:
    return f"techniques/{slugify(name)}.html"


def tactic_link(name: str) -> str:
    return f"tactics/{slugify(name)}.html"


def sort_techniques(names: list[str]) -> list[str]:
    return sorted(names, key=lambda item: (item.split(":")[0].lower(), item.lower()))


def build_index(techniques: dict[str, dict], tactics: list[str], by_tactic: dict[str, list[str]]) -> str:
    columns = []
    for idx, tactic in enumerate(tactics):
        cards = []
        for technique in sort_techniques(by_tactic[tactic]):
            item = techniques[technique]
            is_subtechnique = ":" in technique
            card_class = "technique-card subtechnique" if is_subtechnique else "technique-card"
            other_tactics = [t for t in item["tactics"] if t != tactic]
            badges = "".join(
                f'<span class="mini-badge">{escape(other)}</span>' for other in other_tactics
            )
            cards.append(
                f"""        <a class="{card_class}" href="{technique_link(technique)}">
          <span class="technique-name">{escape(technique)}</span>
          {f'<span class="related-tactics">{badges}</span>' if badges else ''}
        </a>"""
            )
        columns.append(
            f"""      <section class="matrix-column" style="--accent-index: {idx}">
        <a class="tactic-heading" href="{tactic_link(tactic)}">
          <span>{escape(tactic)}</span>
          <strong>{len(by_tactic[tactic])}</strong>
        </a>
{chr(10).join(cards)}
      </section>"""
        )

    body = f"""{page_header("overview")}
  <main>
    <section class="intro">
      <div>
        <p class="eyebrow">MITRE ATT&CK for ICS</p>
        <h1>Dataset TTP Mapping Matrix</h1>
        <p class="lede">A static overview of the tactics and techniques used in the dataset annotation mapping.</p>
      </div>
      <dl class="stats" aria-label="Mapping statistics">
        <div><dt>{len(tactics)}</dt><dd>Tactics</dd></div>
        <div><dt>{len(techniques)}</dt><dd>Techniques</dd></div>
      </dl>
    </section>

    <section class="toolbar" aria-label="Matrix controls">
      <label class="search">
        <span>Search</span>
        <input id="matrix-search" type="search" placeholder="Filter techniques or tactics">
      </label>
      <button id="clear-search" type="button">Clear</button>
    </section>

    <section class="matrix-wrap" aria-label="MITRE ATT&CK tactic and technique matrix">
      <div class="matrix">
{chr(10).join(columns)}
      </div>
    </section>
  </main>
  <script src="site.js"></script>"""
    return html_page("Matrix", body)


def build_tactic_page(tactic: str, techniques: dict[str, dict], names: list[str]) -> str:
    cards = []
    for technique in sort_techniques(names):
        desc = techniques[technique].get("description", "")
        cards.append(
            f"""        <a class="detail-card" href="../{technique_link(technique)}">
          <strong>{escape(technique)}</strong>
          <span>{escape(desc[:190])}{'...' if len(desc) > 190 else ''}</span>
        </a>"""
        )

    body = f"""{page_header()}
  <main class="detail-main">
    <nav class="breadcrumbs" aria-label="Breadcrumbs">
      <a href="../index.html">Matrix</a>
      <span>{escape(tactic)}</span>
    </nav>
    <section class="detail-hero tactic-hero">
      <p class="eyebrow">Tactic</p>
      <h1>{escape(tactic)}</h1>
      <p class="lede">{len(names)} mapped techniques</p>
    </section>
    <section class="detail-list" aria-label="Techniques for {escape(tactic)}">
{chr(10).join(cards)}
    </section>
  </main>"""
    return html_page(tactic, body, depth=1)


def build_technique_page(name: str, item: dict) -> str:
    tactic_chips = "".join(
        f'<a class="chip" href="../{tactic_link(tactic)}">{escape(tactic)}</a>'
        for tactic in item.get("tactics", [])
    )
    description = escape(item.get("description", "No description available."))
    body = f"""{page_header()}
  <main class="detail-main">
    <nav class="breadcrumbs" aria-label="Breadcrumbs">
      <a href="../index.html">Matrix</a>
      <span>{escape(name)}</span>
    </nav>
    <article class="detail-hero">
      <p class="eyebrow">Technique</p>
      <h1>{escape(name)}</h1>
      <div class="chip-row" aria-label="Associated tactics">
        {tactic_chips}
      </div>
      <section class="description">
        <h2>Description</h2>
        <p>{description}</p>
      </section>
    </article>
  </main>"""
    return html_page(name, body, depth=1)


def write_static_assets(output_dir: Path) -> None:
    (output_dir / "favicon.svg").write_text(
        """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="12" fill="#18343c"/>
  <text x="32" y="38" text-anchor="middle" font-family="Arial, sans-serif" font-size="18" font-weight="800" fill="#ffffff">TTP</text>
</svg>
""",
        encoding="utf-8",
    )

    (output_dir / "styles.css").write_text(
        """* {
  box-sizing: border-box;
}

:root {
  color-scheme: light;
  --bg: #f4f6f7;
  --panel: #ffffff;
  --ink: #172026;
  --muted: #62727d;
  --line: #d9e0e4;
  --accent: #1f7a8c;
  --accent-soft: #e4f4f6;
  --shadow: 0 18px 45px rgba(27, 42, 51, 0.08);
}

body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.5;
}

a {
  color: inherit;
  text-decoration: none;
}

.site-header {
  position: sticky;
  top: 0;
  z-index: 10;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  padding: 14px clamp(18px, 4vw, 44px);
  background: rgba(244, 246, 247, 0.9);
  border-bottom: 1px solid var(--line);
  backdrop-filter: blur(14px);
}

.brand {
  display: inline-flex;
  align-items: center;
  gap: 12px;
}

.brand-mark {
  display: grid;
  place-items: center;
  width: 42px;
  height: 42px;
  border-radius: 8px;
  background: #18343c;
  color: #fff;
  font-weight: 800;
  font-size: 0.8rem;
}

.brand strong,
.brand small {
  display: block;
}

.brand small {
  color: var(--muted);
  font-size: 0.78rem;
}

.site-header nav {
  display: flex;
  gap: 8px;
}

.site-header nav a {
  padding: 8px 12px;
  border-radius: 8px;
  color: var(--muted);
  font-weight: 650;
}

.site-header nav a.active,
.site-header nav a:hover {
  background: var(--panel);
  color: var(--ink);
}

main {
  padding: 34px clamp(16px, 4vw, 44px) 56px;
}

.intro {
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 28px;
  margin-bottom: 22px;
}

.eyebrow {
  margin: 0 0 8px;
  color: var(--accent);
  font-size: 0.76rem;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

h1 {
  max-width: 920px;
  margin: 0;
  font-size: clamp(2rem, 5vw, 4.6rem);
  line-height: 0.98;
  letter-spacing: 0;
}

.lede {
  max-width: 760px;
  margin: 14px 0 0;
  color: var(--muted);
  font-size: 1.04rem;
}

.stats {
  display: grid;
  grid-template-columns: repeat(2, minmax(98px, 1fr));
  gap: 10px;
  margin: 0;
}

.stats div {
  min-width: 112px;
  padding: 14px;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  box-shadow: var(--shadow);
}

.stats dt {
  font-size: 1.8rem;
  font-weight: 850;
}

.stats dd {
  margin: 0;
  color: var(--muted);
  font-size: 0.84rem;
}

.toolbar {
  display: flex;
  align-items: end;
  gap: 10px;
  margin: 18px 0;
}

.search {
  display: grid;
  gap: 6px;
  width: min(460px, 100%);
}

.search span {
  color: var(--muted);
  font-size: 0.8rem;
  font-weight: 750;
}

.search input {
  width: 100%;
  min-height: 42px;
  padding: 9px 12px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
  color: var(--ink);
  font: inherit;
}

button {
  min-height: 42px;
  padding: 9px 14px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #18343c;
  color: #fff;
  font: inherit;
  font-weight: 750;
  cursor: pointer;
}

.matrix-wrap {
  overflow-x: auto;
  padding-bottom: 14px;
}

.matrix {
  display: grid;
  grid-template-columns: repeat(11, minmax(210px, 1fr));
  align-items: start;
  gap: 10px;
  min-width: 2450px;
}

.matrix-column {
  display: grid;
  gap: 8px;
}

.tactic-heading {
  display: flex;
  min-height: 72px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px;
  border-radius: 8px;
  background: hsl(calc(188 + var(--accent-index) * 13) 44% 28%);
  color: #fff;
  font-weight: 850;
  box-shadow: var(--shadow);
}

.tactic-heading strong {
  display: grid;
  place-items: center;
  min-width: 32px;
  height: 32px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.18);
  font-size: 0.9rem;
}

.technique-card {
  display: grid;
  gap: 8px;
  min-height: 70px;
  padding: 11px 12px;
  border: 1px solid var(--line);
  border-left: 5px solid hsl(calc(188 + var(--accent-index) * 13) 44% 36%);
  border-radius: 8px;
  background: var(--panel);
  box-shadow: 0 8px 22px rgba(27, 42, 51, 0.05);
}

.technique-card:hover,
.detail-card:hover,
.chip:hover {
  border-color: var(--accent);
  box-shadow: 0 14px 30px rgba(27, 42, 51, 0.11);
  transform: translateY(-1px);
}

.subtechnique {
  margin-left: 16px;
  background: #fbfcfc;
}

.technique-name {
  font-weight: 750;
  line-height: 1.25;
}

.related-tactics {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.mini-badge {
  padding: 2px 6px;
  border-radius: 999px;
  background: var(--accent-soft);
  color: #23535d;
  font-size: 0.68rem;
  font-weight: 750;
}

.breadcrumbs {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 24px;
  color: var(--muted);
  font-size: 0.9rem;
}

.breadcrumbs a {
  color: var(--accent);
  font-weight: 750;
}

.breadcrumbs span::before {
  content: "/";
  margin-right: 8px;
  color: #99a6ad;
}

.detail-main {
  max-width: 1120px;
  margin: 0 auto;
}

.detail-hero {
  padding: clamp(22px, 5vw, 42px);
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
  box-shadow: var(--shadow);
}

.detail-hero h1 {
  max-width: 940px;
  font-size: clamp(2rem, 6vw, 4.2rem);
}

.tactic-hero {
  background: #18343c;
  color: #fff;
}

.tactic-hero .lede,
.tactic-hero .eyebrow {
  color: #c8e4e8;
}

.chip-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 20px;
}

.chip {
  padding: 8px 10px;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: var(--accent-soft);
  color: #23535d;
  font-weight: 750;
}

.description {
  max-width: 840px;
  margin-top: 34px;
  padding-top: 24px;
  border-top: 1px solid var(--line);
}

.description h2 {
  margin: 0 0 10px;
  font-size: 1rem;
}

.description p {
  margin: 0;
  color: #34444d;
  font-size: 1.05rem;
}

.detail-list {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 12px;
  margin-top: 16px;
}

.detail-card {
  display: grid;
  gap: 8px;
  min-height: 142px;
  padding: 16px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
  box-shadow: 0 8px 22px rgba(27, 42, 51, 0.05);
}

.detail-card strong {
  font-size: 1.05rem;
}

.detail-card span {
  color: var(--muted);
  font-size: 0.92rem;
}

.is-hidden {
  display: none;
}

@media (max-width: 760px) {
  .site-header,
  .intro,
  .toolbar {
    align-items: stretch;
    flex-direction: column;
  }

  .site-header {
    position: static;
  }

  .stats {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .matrix {
    grid-template-columns: repeat(11, 210px);
  }
}
""",
        encoding="utf-8",
    )

    (output_dir / "site.js").write_text(
        """const searchInput = document.querySelector("#matrix-search");
const clearButton = document.querySelector("#clear-search");
const columns = [...document.querySelectorAll(".matrix-column")];

function normalize(value) {
  return value.toLowerCase().trim();
}

function applyFilter() {
  const query = normalize(searchInput.value);
  columns.forEach((column) => {
    const headingText = normalize(column.querySelector(".tactic-heading").innerText);
    let visibleCards = 0;
    column.querySelectorAll(".technique-card").forEach((card) => {
      const matches = !query || headingText.includes(query) || normalize(card.innerText).includes(query);
      card.classList.toggle("is-hidden", !matches);
      if (matches) visibleCards += 1;
    });
    column.classList.toggle("is-hidden", query && visibleCards === 0 && !headingText.includes(query));
  });
}

if (searchInput && clearButton) {
  searchInput.addEventListener("input", applyFilter);
  clearButton.addEventListener("click", () => {
    searchInput.value = "";
    applyFilter();
    searchInput.focus();
  });
}
""",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        default="../dataset_annotation/mitrev19-techniques-compact.json",
        help="Path to mitrev19-techniques-compact.json",
    )
    parser.add_argument("--output", default=".", help="Directory for generated site")
    args = parser.parse_args()

    source = Path(args.source)
    output_dir = Path(args.output)
    data = json.loads(source.read_text(encoding="utf-8"))
    techniques = data["techniques"]

    by_tactic: dict[str, list[str]] = {}
    for name, item in techniques.items():
        for tactic in item.get("tactics", []):
            by_tactic.setdefault(tactic, []).append(name)

    ordered_tactics = [t for t in TACTIC_ORDER if t in by_tactic]
    ordered_tactics.extend(sorted(t for t in by_tactic if t not in ordered_tactics))

    (output_dir / "tactics").mkdir(parents=True, exist_ok=True)
    (output_dir / "techniques").mkdir(parents=True, exist_ok=True)

    write_static_assets(output_dir)
    (output_dir / "index.html").write_text(
        build_index(techniques, ordered_tactics, by_tactic), encoding="utf-8"
    )

    for tactic in ordered_tactics:
        (output_dir / tactic_link(tactic)).write_text(
            build_tactic_page(tactic, techniques, by_tactic[tactic]), encoding="utf-8"
        )

    for name, item in techniques.items():
        (output_dir / technique_link(name)).write_text(
            build_technique_page(name, item), encoding="utf-8"
        )

    print(f"Generated {len(techniques)} technique pages and {len(ordered_tactics)} tactic pages.")


if __name__ == "__main__":
    main()
