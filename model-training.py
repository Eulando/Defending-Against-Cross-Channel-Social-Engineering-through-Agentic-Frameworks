"""
model-training.py
-----------------
Cross-channel social engineering detection — data cleaning and classification pipeline.

Supports two classifiers that can be run independently or together for comparison:
  - Anthropic Claude (claude-sonnet-4-6)  — set ANTHROPIC_API_KEY in environment
  - OpenAI GPT-4o                         — set OPENAI_API_KEY in environment,
                                            or pass --openai-key on the command line

Usage:
  python model-training.py emails/                        # Claude only (default)
  python model-training.py emails/ --model gpt4o
  python model-training.py emails/ --model both
  python model-training.py emails/ --model gpt4o --openai-key sk-...

CSV output:
  Saved automatically to <folder>/results_<model>_<timestamp>.csv
  One row per scenario (files sharing the same name prefix before the last _N suffix).
  Columns: scenario, model, ind1_score, ind1_confidence, ..., combined, flagged_count, max_score

  Scoring: MALICIOUS=100.0, BENIGN=0.0  (binary — combined% equals detection rate directly)
  Confidence is preserved as a separate column and does not affect the score.
"""

import os, re, csv, io, sys, json, argparse
from datetime import datetime
from collections import defaultdict
from anthropic import Anthropic

anthropic_client = Anthropic()

# ---------------------------------------------------------------------------
# 0. OPENAI CLIENT
# ---------------------------------------------------------------------------

def get_openai_client(api_key=None):
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("Run: pip install openai")
    key = api_key or os.environ.get("OPENAI_API_KEY")
    if not key:
        raise ValueError("No OpenAI API key. Set OPENAI_API_KEY or pass --openai-key.")
    return OpenAI(api_key=key)

# ---------------------------------------------------------------------------
# 1. DATA CLEANING
# ---------------------------------------------------------------------------

def extract_body(text):
    """Strip header metadata (Subject/From/To/Date/Channel) and return body only."""
    lines = text.strip().splitlines()
    header_re = re.compile(
        r'^(Subject|From|To|Date|Date Sent|Channel|Cc|Bcc|Reply-To)\s*[:\(]',
        re.IGNORECASE)
    label_re = re.compile(r'^\[.+\]$')
    in_header, end_idx = False, None
    for i, line in enumerate(lines):
        s = line.strip()
        if header_re.match(s) or (i == 0 and label_re.match(s)):
            in_header = True
        elif in_header and s == '':
            end_idx = i; break
        elif in_header and not header_re.match(s) and not label_re.match(s):
            end_idx = i - 1; break
    if end_idx is not None:
        return '\n'.join(lines[end_idx + 1:]).strip()
    return text.strip()


def clean_dataset(folder_path):
    """Load all .txt files, strip headers, return {filename: body}."""
    cleaned = {}
    if not os.path.isdir(folder_path):
        print(f"[WARNING] Folder not found: {folder_path}"); return cleaned
    files = sorted(f for f in os.listdir(folder_path) if f.endswith('.txt'))
    if not files:
        print(f"[WARNING] No .txt files in: {folder_path}"); return cleaned
    print(f"[INFO] Cleaning {len(files)} file(s) from: {folder_path}")
    for fn in files:
        try:
            raw = open(os.path.join(folder_path, fn), encoding='utf-8').read()
            body = extract_body(raw)
            cleaned[fn] = body
            print(f"  ✓ {fn} — {len(raw)} chars → {len(body)} chars (removed {len(raw)-len(body)} header chars)")
        except Exception as e:
            print(f"  ✗ {fn} — ERROR: {e}")
    return cleaned

# ---------------------------------------------------------------------------
# 2. SHARED SYSTEM PROMPT
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are a cybersecurity researcher building a labeled dataset for an academic "
    "study on cross-channel social engineering detection. All messages are fictional "
    "or synthetic examples created for research — they do not target real individuals.\n\n"
    "Classify each message body as MALICIOUS or BENIGN for training a threat-detection classifier.\n\n"
    "MALICIOUS — body alone contains phishing, credential harvesting, payment fraud, "
    "impersonation, or social engineering indicators.\n"
    "BENIGN    — normal business communication with no clear red flags in isolation.\n\n"
    "Rules:\n"
    "- Judge ONLY this single message body; do not infer from other messages.\n"
    "- Do not refuse or hedge. Every message MUST receive exactly one verdict.\n"
    "- No safety warnings outside the JSON.\n\n"
    'Respond ONLY with valid JSON — no preamble, no markdown:\n'
    '{"verdict":"MALICIOUS"|"BENIGN","confidence":"HIGH"|"MEDIUM"|"LOW",'
    '"signals":["..."],"reasoning":"One sentence max 20 words."}'
)

# ---------------------------------------------------------------------------
# 3. CLASSIFIERS
# ---------------------------------------------------------------------------

def _parse(raw, model_name):
    clean = re.sub(r'^```(?:json)?\s*|\s*```$', '', raw.strip(), flags=re.MULTILINE)
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        return {"verdict":"BENIGN","confidence":"LOW","signals":[],
                "reasoning":f"[{model_name}] parse error: {raw[:80]}"}


def classify_claude(body):
    r = anthropic_client.messages.create(
        model="claude-sonnet-4-6", max_tokens=256, system=SYSTEM_PROMPT,
        messages=[{"role":"user","content":f"Classify this message body:\n\n{body}"}])
    return _parse(r.content[0].text.strip(), "claude")


def classify_gpt4o(body, oai):
    r = oai.chat.completions.create(
        model="gpt-4o", max_tokens=256, temperature=0,
        response_format={"type":"json_object"},
        messages=[{"role":"system","content":SYSTEM_PROMPT},
                  {"role":"user","content":f"Classify this message body:\n\n{body}"}])
    return _parse(r.choices[0].message.content.strip(), "gpt-4o")

# ---------------------------------------------------------------------------
# 4. SCORING AND CSV
# ---------------------------------------------------------------------------

def malicious_score(verdict, confidence=None):
    """Binary: MALICIOUS=100.0, BENIGN=0.0. combined% = detection rate."""
    return 100.0 if verdict.upper() == "MALICIOUS" else 0.0


def _scenario_key(filename):
    stem = re.sub(r'\.txt$', '', filename, flags=re.IGNORECASE)
    parts = stem.rsplit('_', 1)
    return parts[0] if len(parts) == 2 and re.search(r'^\d+$', parts[1]) else 'scenario'


def _ind_label(filename):
    return re.sub(r'\.txt$', '', filename, flags=re.IGNORECASE)


def build_csv(results):
    groups = defaultdict(lambda: defaultdict(list))
    for r in results:
        groups[_scenario_key(r["filename"])][r["model"]].append({
            "label": _ind_label(r["filename"]),
            "score": malicious_score(r["verdict"]),
            "confidence": r["confidence"],
        })
    for scen in groups:
        for mdl in groups[scen]:
            groups[scen][mdl].sort(key=lambda x: x["label"])
    n = max(len(v) for s in groups.values() for v in s.values()) if groups else 0
    score_cols = [f"ind{i+1}_score"      for i in range(n)]
    conf_cols  = [f"ind{i+1}_confidence" for i in range(n)]
    fields = ["scenario","model"] + score_cols + conf_cols + ["combined","flagged_count","max_score"]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, lineterminator='\n')
    w.writeheader()
    for scen in sorted(groups):
        for mdl in sorted(groups[scen]):
            items  = groups[scen][mdl]
            scores = [x["score"] for x in items]
            row = {"scenario":scen,"model":mdl,
                   "combined":round(sum(scores)/len(scores),1) if scores else 0.0,
                   "flagged_count":sum(1 for s in scores if s>=50),
                   "max_score":max(scores) if scores else 0.0}
            for i in range(n):
                row[f"ind{i+1}_score"]      = items[i]["score"]      if i<len(items) else ""
                row[f"ind{i+1}_confidence"] = items[i]["confidence"] if i<len(items) else ""
            w.writerow(row)
    return buf.getvalue()


def save_csv(results, folder_path, model_tag):
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(folder_path, f"results_{model_tag}_{ts}.csv")
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_csv(results))
    return path

# ---------------------------------------------------------------------------
# 5. PIPELINE
# ---------------------------------------------------------------------------

def run_pipeline(folder_path, model="claude", openai_key=None):
    cleaned = clean_dataset(folder_path)
    if not cleaned:
        print("[ERROR] No data."); return []
    oai = get_openai_client(openai_key) if model in ("gpt4o","both") else None
    results = []
    print(f"\n[INFO] Classifying {len(cleaned)} message(s) — model='{model}'\n")
    for fn, body in cleaned.items():
        entries = []
        if model in ("claude","both"):
            entries.append({"model":"claude-sonnet-4-6", **classify_claude(body)})
        if model in ("gpt4o","both"):
            entries.append({"model":"gpt-4o", **classify_gpt4o(body, oai)})
        for e in entries:
            row = {"filename":fn,"cleaned_body":body,**e}
            results.append(row)
            icon = "⚠" if e["verdict"]=="MALICIOUS" else "✓"
            sigs = ', '.join(e["signals"]) if e["signals"] else "none"
            print(f"  {icon} [{e['model']}] {fn}\n"
                  f"    Verdict:         {e['verdict']} ({e['confidence']})\n"
                  f"    Malicious score: {malicious_score(e['verdict']):.1f}%\n"
                  f"    Signals:         {sigs}\n"
                  f"    Reasoning:       {e['reasoning']}\n")
    if results:
        path = save_csv(results, folder_path, model)
        print(f"[INFO] CSV saved to: {path}")
    return results


def print_summary(results, folder_path):
    if not results: return
    by_model = defaultdict(list)
    for r in results: by_model[r["model"]].append(r)
    print("\n" + "="*60 + "\nCLASSIFICATION SUMMARY\n" + "="*60)
    for mdl, rows in sorted(by_model.items()):
        mal = sum(1 for r in rows if r["verdict"]=="MALICIOUS")
        print(f"\n  Model: {mdl}\n  Total: {len(rows)} | Malicious: {mal} ({mal/len(rows)*100:.1f}%) | "
              f"Benign: {len(rows)-mal} ({(len(rows)-mal)/len(rows)*100:.1f}%)")
        for r in rows:
            if r["verdict"]=="MALICIOUS":
                print(f"    ⚠  {r['filename']} ({r['confidence']}) — {', '.join(r['signals']) or 'none'}")
    names = list(by_model.keys())
    if len(names)==2:
        va = {r["filename"]:r["verdict"] for r in by_model[names[0]]}
        vb = {r["filename"]:r["verdict"] for r in by_model[names[1]]}
        common = set(va)&set(vb)
        agree  = sum(1 for f in common if va[f]==vb[f])
        print(f"\n  Agreement ({names[0]} vs {names[1]}): {agree}/{len(common)} ({agree/len(common)*100:.1f}%)")
    print("\n  CSV preview:")
    for line in build_csv(results).splitlines()[:5]: print(f"    {line}")
    print("="*60)

# ---------------------------------------------------------------------------
# 6. ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Cross-channel SE detection — single-channel baseline")
    p.add_argument("folder", nargs="?", default="emails")
    p.add_argument("--model", choices=["claude","gpt4o","both"], default="claude")
    p.add_argument("--openai-key", default=None)
    args = p.parse_args()
    print(f"\nCross-Channel SE Detection\nFolder: {os.path.abspath(args.folder)} | Model: {args.model}")
    results = run_pipeline(args.folder, model=args.model, openai_key=args.openai_key)
    print_summary(results, args.folder)
