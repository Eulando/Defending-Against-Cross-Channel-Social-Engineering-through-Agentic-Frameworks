#!/bin/bash
# Run from inside the repo:
#   cd ~/codes/Defending-Against-Cross-Channel-Social-Engineering-through-Agentic-Frameworks
#   bash commit.sh

set -e
cd "$(dirname "$0")"

echo "=== Creating folder structure ==="
mkdir -p data/scenarios/pelicanbridgecapital

echo "=== Writing scenario emails ==="
cat > data/scenarios/pelicanbridgecapital/email1.txt << 'ENDOFFILE'
Subject: Introduction - Harlow and Vance Advisory Partnership
From: "Sarah Kimura" <s.kimura@harlowvance-adv1sory.com>
To: partnerships@pelicanbridgecapital.com
Date: Mon, Jul 21, 2026 9:12 AM

Hi,

My name is Sarah Kimura and I lead business development at Harlow and Vance Advisory. We work with mid-market investment firms on fund administration and operational efficiency -- your firm came up through our network as a potential fit for a benchmarking project we're running this quarter.

Nothing formal at this stage -- I just wanted to introduce myself and see if there's an interest in a brief call. We've worked with a few firms in your space and found that operational benchmarking tends to surface some useful cost comparisons.

Would anyone on your team be open to a 20-minute call this week or next?

Best,
Sarah Kimura
Business Development, Harlow and Vance Advisory
+1 (312) 904-0187
ENDOFFILE

cat > data/scenarios/pelicanbridgecapital/email2.txt << 'ENDOFFILE'
Subject: Re: Introduction - Harlow and Vance Advisory Partnership
From: "Sarah Kimura" <s.kimura@harlowvance-adv1sory.com>
To: partnerships@pelicanbridgecapital.com
Date: Wed, Jul 23, 2026 2:34 PM

Hi again,

Thanks for the warm response -- glad to hear you're open to connecting. Before our call on Friday I wanted to share a couple of questions so you're not caught off guard.

For the benchmarking comparison, it would help to know roughly what fund administration platform you're currently running on -- whether that's Advent, Allvue, Eze, or something proprietary -- and how many funds you're currently administering. We keep all of this in aggregate so nothing firm-specific ever surfaces in the report.

Also, who typically owns the vendor and fee approval process at Pelican Bridge? Is that managed at the COO level, or does it flow through a finance committee? Just trying to understand the right stakeholder to loop in if the benchmarking yields anything actionable.

Looking forward to Friday.

Sarah
ENDOFFILE

cat > data/scenarios/pelicanbridgecapital/email3.txt << 'ENDOFFILE'
Subject: Post-Call Follow-Up - Benchmark Report Access
From: "Sarah Kimura" <s.kimura@harlowvance-adv1sory.com>
To: partnerships@pelicanbridgecapital.com
Date: Mon, Jul 28, 2026 10:05 AM

Hi,

Great speaking with you on Friday. As promised, I'm sending over access to the Q2 2026 Fund Operations Benchmark Report -- it's gated but I've set up a direct access link for Pelican Bridge.

You can download the report here using your firm email:
https://harlowvance-adv1sory.com/reports/q2-benchmark?access=PBC-2026&login=required

Let me know if you have any trouble logging in -- the portal uses SSO so it should match your existing credentials.

I'll follow up early next week once you've had a chance to review. Happy to walk through the findings on another call if that's useful.

Best,
Sarah
ENDOFFILE

cat > data/scenarios/pelicanbridgecapital/email4.txt << 'ENDOFFILE'
Subject: Updated Invoice - Fund Administration Review Q2 2026
From: "Harlow and Vance Billing" <billing@harlowvance-adv1sory.com>
To: ap@pelicanbridgecapital.com
Date: Thu, Jul 31, 2026 8:49 AM

Dear Accounts Payable Team,

Please find attached the updated invoice for the Fund Administration Benchmarking Engagement -- Q2 2026 (Invoice #HV-4402, $12,800.00), reflecting the revised scope agreed with your partnerships team.

As discussed with Sarah Kimura, payment should be directed to our updated banking details, which changed as of July 1 following our acquisition by the Vantage Group:

Bank: Meridian Commercial Bank
Routing Number: 082736441
Account Number: 7719204853
Account Name: Harlow Vance Advisory LLC

Please process by August 8 to avoid a late fee. If you have questions, contact our billing team at billing@harlowvance-adv1sory.com or reach Sarah directly.

Thank you,
Harlow and Vance Billing
ENDOFFILE

echo "=== Staging ==="
git add model-training.py
git add data/

echo "=== Committing ==="
git commit -m "Add model-training pipeline and Pelican Bridge Capital scenario

model-training.py:
- extract_body(): strips email headers so classifiers see body only
- clean_dataset(): applies cleaning across a folder of .txt files
- classify_claude(): Anthropic API (claude-sonnet-4-6)
- classify_gpt4o(): OpenAI API with research framing to suppress safety refusals
- malicious_score(): binary MALICIOUS=100 BENIGN=0 so combined equals detection rate
- build_csv() / save_csv(): per-scenario CSV with ind_score, ind_confidence,
  combined, flagged_count, max_score columns
- CLI: --model claude/gpt4o/both and --openai-key

data/scenarios/pelicanbridgecapital/:
- 4-email slow-burn BEC invoice fraud scenario (fictional Pelican Bridge Capital)
- Cold intro, intel gathering, credential harvest, payment redirect
- Single-channel detection rate 50 percent (emails 1-2 benign, 3-4 flagged)"

echo "=== Pushing ==="
git push origin HEAD

echo ""
echo "Done. View at:"
echo "https://github.com/Eulando/Defending-Against-Cross-Channel-Social-Engineering-through-Agentic-Frameworks"
