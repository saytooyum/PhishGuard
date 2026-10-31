# PhishGuard

A beginner-friendly, rule-based phishing detector built with Python and Streamlit.
It checks URLs and email text for common phishing indicators such as missing HTTPS,
IP-address hosts, urgent language, and suspicious sender domains.

## Setup

**Requirements:** Python 3.9 or newer.

1. Create and activate a virtual environment (recommended):

   ```bash
   python -m venv .venv
   source .venv/bin/activate      # macOS / Linux
   .venv\Scripts\activate         # Windows
   ```

2. Install the required package:

   ```bash
   pip install -r requirements.txt
   ```

## Run the app

```bash
streamlit run app.py
```

The app will open in your browser automatically.

## Run the tests

```bash
python -m unittest test_analyzer.py
```

## Project structure

```
Phishing Guard/
├── analyzer.py          # Rule-based analysis logic
├── app.py               # Streamlit interface
├── demo_inputs.txt      # Sample inputs for manual testing
├── requirements.txt     # Python dependencies
├── test_analyzer.py     # Unit tests
└── README.md
```

## Disclaimer

> PhishGuard uses simple pattern-based rules. Its results are **educational
> indicators only** and can be wrong — both false positives (flagging safe
> content) and false negatives (missing real threats) are possible. Always
> apply your own judgement and consult a security professional when in doubt.
