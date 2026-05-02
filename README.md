# Browser Isolation in the Wild

![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)

A research-oriented toolkit for measuring browser isolation headers, iframe deployment, and isolation inconsistencies across real-world websites.

## What this project does

This repository collects and analyzes web security headers and iframe behavior to identify browser isolation gaps such as:

- COOP/COEP adoption
- CORP enforcement for cross-origin embeds
- sandboxed vs non-sandboxed iframes
- header + iframe policy inconsistencies
- login/register page coverage for the same domain

## Why this project is useful

It helps security researchers and engineers understand how sites deploy isolation policies in practice and where mixed or missing signals can leave content exposed. The project is useful for:

- empirical analysis of browser isolation mechanisms
- detecting real-world misconfigurations
- generating datasets for research papers
- comparing header adoption and iframe security patterns

## Getting started

### Prerequisites

- Python 3.12 or later
- Google Chrome installed
- Internet access for Selenium browsing and ChromeDriver downloads

### Install dependencies

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

If you prefer macOS/Linux:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Run the crawler

The main data collection script is `test.py`. It consumes a site list and writes results to `results.csv`.

```bash
python test.py
```

#### Required input data

`test.py` expects a `top-1m.csv` file in the repository root. If you do not have that file, edit `SITES` in `test.py` to define a small list of domains manually.

### Analyze the results

After crawling, open `notebook.ipynb` to explore the dataset, apply isolation rules, and visualize findings in Jupyter.

```bash
jupyter notebook notebook.ipynb
```

## Project structure

- `test.py` — Selenium-based crawler that collects header and iframe metrics from sites
- `results.csv` — sample output format for collected site measurements
- `notebook.ipynb` — analysis notebook for encoding rules and plotting results
- `requirements.txt` — Python dependency list
- `setup.md` — environment setup notes
- `LICENSE` — MIT license

## Contribution

Contributions are welcome. Please use GitHub issues for bugs, feature requests, or research questions. If you want to contribute code, open a pull request with a focused change.

If you add features that change output columns or analysis rules, please update `results.csv` and `notebook.ipynb` accordingly.

## Support

For questions or help, use the repository issue tracker.

If you need more context about execution, start with `setup.md` for environment setup.

## Maintainers

Maintained by Margaret-P and AnotherDaphne.

## License

This project is licensed under the [MIT License](LICENSE).
