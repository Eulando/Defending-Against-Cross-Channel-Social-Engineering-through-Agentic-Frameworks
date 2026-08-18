# Cross-Channel Dataset Pipeline v2

A clean, API-driven research pipeline for generating, validating, blindly scoring, and sorting synthetic
cross-channel social-engineering datasets. It supports four predeclared experiment modes:

| Index range | Mode | Expected individual result | Expected combined result |
|---|---|---|---|
| `0–99` | Bottom-up malicious | benign/low score | malicious/high score |
| `100–199` | Top-down malicious | benign/low score | malicious/high score |
| `200–299` | Bottom-up benign | benign/low score | benign/low score |
| `300–399` | Top-down benign | benign/low score | benign/low score |

Ranges are hard-coded and tested to prevent overlap.

## Methodological safeguards

- Generation uses structured Pydantic output through the OpenAI Responses API.
- Four different channels and targets are required by schema validation.
- Every individual message declares one atomic request.
- The combined message must preserve exactly those four requests in the same order.
- An independent model audits semantic linkage and rejects combined messages that add a fifth action.
- Classification receives only one message body at a time, hiding mode, labels, neighboring messages, and metadata.
- Generation and scoring models must differ unless explicitly overridden.
- Thresholds are declared before generation and recorded in `summary.json`.
- Rejected attempts remain available for failure-rate analysis; only passing scenarios enter `accepted/`.

OpenAI Structured Outputs are used so API responses follow the declared schema rather than relying on fragile
Markdown parsing. See the [official OpenAI Structured Outputs documentation](https://developers.openai.com/api/docs/guides/structured-outputs).

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
```

Add your API key to `.env`. Never commit that file. Select models your API project can access:

```dotenv
OPENAI_API_KEY=your-key
OPENAI_GENERATION_MODEL=gpt-5-mini
OPENAI_SCORING_MODEL=gpt-4.1-mini
```

## Run

Start with one accepted scenario per mode:

```bash
crosschannel --artifacts artifacts run --mode all --count 1 --max-attempts 5
```

Then scale to 100 accepted scenarios per mode:

```bash
crosschannel --artifacts artifacts run --mode all --count 100 --max-attempts 10
```

The run is resumable. Existing accepted indices are skipped.

Important: one candidate normally requires **seven API calls**—one generation, one linkage audit, four individual
scores, and one combined score. Four hundred accepted scenarios require at least 2,800 calls, and quality retries
increase that number. Run a small pilot and inspect cost/quality before scaling.

## Output

```text
artifacts/
├── accepted/
│   └── <mode>/
│       ├── ind1/dataN.txt
│       ├── ind2/dataN.txt
│       ├── ind3/dataN.txt
│       ├── ind4/dataN.txt
│       ├── combined/dataN.txt
│       └── metadata/dataN.json
├── candidates/<mode>/dataN_attemptK.json
├── rejected/<mode>/dataN_attemptK.json
├── manifest.csv
├── scores.csv
└── summary.json
```

The body-only `.txt` files are suitable for blind classifier evaluation. Metadata, generation notes, linkage audits,
and labels remain separate.

## Tests

Tests use a deterministic fake provider and make no API calls:

```bash
pytest
```

## Research limitations

Passing an automated score does not establish ground truth. Before publication, freeze thresholds, sample scenarios
for human review, report rejection rates, test with models from more than one provider where permitted, and prevent
generator-family leakage between training and evaluation splits.
