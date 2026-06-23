# Dataset TTP Overview

Static GitHub Pages overview for the MITRE ATT&CK tactics and techniques used in the dataset mapping.

## Regenerate the site

From this repository:

```bash
python3 generate_site.py
```

The generator reads:

```text
../dataset_annotation/mitrev19-techniques-compact.json
```

It writes `index.html`, `styles.css`, `site.js`, and the static tactic and technique detail pages.

## Deploy with GitHub Pages

In GitHub, open the repository settings and set Pages to deploy from the `main` branch using the repository root.
