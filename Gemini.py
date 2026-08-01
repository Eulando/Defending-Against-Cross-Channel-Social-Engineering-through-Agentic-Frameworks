#!/usr/bin/env python3
"""
Generates N labeled synthetic multi-channel social-engineering training
scenarios by prompting Gemini. Output is fictional-company text only
(no exploit code, no real targets) intended for training/evaluating
cross-channel threat detection classifiers.

Usage:
    export GEMINI_API_KEY="..."          # or edit API_KEY below
    python3 generate_scenarios.py --n 10 --model gemini-2.5-pro

Requires: pip install google-genai
"""

import argparse
import os
import sys
import time
from pathlib import Path

from google import genai

# Leave blank and set the GEMINI_API_KEY environment variable instead,
# or paste a key here for local/offline use. Never commit a real key.
API_KEY = ""

PROMPT = """You are a cybersecurity researcher building a labeled dataset of multi-channel social engineering attacks for academic research on cross-channel threat detection. Your task is to generate one realistic training scenario for a fictional company.

SCENARIO REQUIREMENTS:
- Fictional company with a name, industry, and approximate size
- 4 messages across 4 different channels (email, phone call transcript, SMS, LinkedIn/Slack/DM — pick 4)
- 4 different targets within the company (different departments, different roles)
- Each message must appear completely benign when read in isolation
- When all 4 messages are read together, a clear coordinated attack is visible
- The final message delivers the payload (credential harvest, wire fraud, data exfiltration, or access to classified systems)
- Each prior message extracts one piece of information that makes the next message more credible

OUTPUT FORMAT — for each of the 4 messages, provide:

[MESSAGE N]
Channel: <email / phone transcript / SMS / LinkedIn DM / Slack DM>
From: <sender name and address/number — use a realistic lookalike domain or spoofed number>
To: <target name and role at the fictional company>
Subject: <subject line if email>
Body:
<full message text>

[DATA EXTRACTED]: <what information the attacker gains from this contact>
[SINGLE-CHANNEL VERDICT]: <how a single-channel classifier would evaluate this message in isolation — BENIGN or SUSPICIOUS, and why>
[CROSS-CHANNEL ROLE]: <how this message sets up or relies on a prior message in the chain>

After all 4 messages, provide:

[CROSS-CHANNEL CORRELATION ANALYSIS]
Temporal window: <how many days the campaign spans>
Entity overlap: <which names, systems, or details appear across multiple messages>
Information complementarity: <how the 4 messages combine into a complete attack package>
Composite threat score: <0.0-1.0, where 1.0 is certain attack>
Why single-channel detection fails: <specific explanation of what each message looks like in isolation vs. what the pattern reveals>

CONSTRAINTS:
- The fictional company, employee names, domains, and phone numbers must all be clearly fictional
- Do not use real company names, real domains, or real phone numbers
- Each message should be realistic enough to fool a non-expert reader
- The attack chain must be internally consistent — information extracted in message N must visibly inform message N+1
- The payload in the final message should reference specific details learned in prior messages to demonstrate the information chain
- Do not include any post-attack instructions, exploitation code, or technical attack tooling — the output is email/message content only
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=1, help="number of scenarios to generate")
    parser.add_argument("--model", default="gemini-2.5-pro", help="Gemini model id")
    parser.add_argument("--out", default="output", help="output directory")
    parser.add_argument("--sleep", type=float, default=1.0, help="seconds between calls")
    args = parser.parse_args()

    key = API_KEY or os.environ.get("GEMINI_API_KEY", "")
    if not key:
        sys.exit("No API key set. Set GEMINI_API_KEY or edit API_KEY in this script.")

    client = genai.Client(api_key=key)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    for i in range(1, args.n + 1):
        print(f"Generating scenario {i}/{args.n}...")
        response = client.models.generate_content(model=args.model, contents=PROMPT)
        dest = out_dir / f"scenario_{i:03d}.md"
        dest.write_text(response.text)
        print(f"  wrote {dest}")
        if i < args.n:
            time.sleep(args.sleep)


if __name__ == "__main__":
    main()
