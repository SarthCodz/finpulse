# FinPulse (HackPSU Fall 2026, FNB Challenge)

A financial confidence engine: a 0-100 score from emergency runway and savings rate,
a 12-month savings projection with APY, expense management, CSV statement import,
a "Can I afford it?" decision check (what a purchase or new bill does to your runway and score),
and a printable report.

## Run
```
pip install -r requirements.txt
streamlit run app.py
```
Demo login: `alex` / `password123`. Data is stored locally in `finpulse.db` (created on first run).
Try `sample_statement.csv` in Manage Expenses -> Import.
