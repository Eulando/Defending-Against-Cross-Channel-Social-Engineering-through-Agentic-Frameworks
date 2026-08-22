# Defending Against Cross-Channel Social Engineering through Agentic Frameworks

Synthetic dataset generator for research on detecting coordinated,
multi-channel social engineering attacks (e.g. email + phone + SMS + DM
chains against a fictional company). Each generated scenario is entirely
fictional and includes per-message single-channel labels plus a
cross-channel correlation analysis, for training/evaluating classifiers
that need to reason across channels rather than per-message.

## Usage

```bash
pip install google-genai
export GEMINI_API_KEY="your-key-here"
python3 generate_scenarios.py --n 10
```

Output scenarios are written to `output/scenario_NNN.md`.
