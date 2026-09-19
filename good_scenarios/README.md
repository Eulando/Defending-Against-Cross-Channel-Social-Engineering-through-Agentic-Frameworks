## good_scenarios/

This folder contains 35 scenarios hand-selected from Grace's dataset
that exhibit the ideal detection pattern identified by Dr. Yoo:

  - All 4 individual emails score < 50 (classifier sees each as BENIGN)
  - Combined email scores >= 70 (classifier sees the full picture as MALICIOUS)

This is the pattern the dataset should maximize: each individual channel
looks like a routine internal communication, but the aggregate reveals
a coordinated social engineering attack.

### Selection criteria (from chatGPT_score.csv)

  all(ind1, ind2, ind3, ind4) < 50  AND  combined >= 70

### Score summary

| Combined score | Count |
|---------------|-------|
| 85            | 16    |
| 75            | 18    |
| 70            |  1    |

### Folder structure

Each scenario has 5 files mirroring Grace's main dataset:

  good_scenarios/
    ind1/dataK.txt   — individual channel email 1
    ind2/dataK.txt   — individual channel email 2
    ind3/dataK.txt   — individual channel email 3
    ind4/dataK.txt   — individual channel email 4
    combined/dataK.txt — combined view (clearly malicious)

### Scenario IDs included

203, 222, 235, 258, 264, 268, 291, 293, 299, 301, 316, 330, 334, 339,
346, 352, 358, 365, 388, 393, 401, 432, 461, 485, 527, 538, 539, 550,
553, 555, 558, 560, 569, 588, 591

### Purpose

Use these as:
1. Positive training examples for the low-ind/high-combined pattern
2. Reference material when rewriting Top-down.py prompt templates
3. Ground truth for evaluating whether new generated scenarios match
   the desired pattern
