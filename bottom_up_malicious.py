#!/usr/bin/env python3
"""Generate Aiden's data0-data99 using Eugene's bottom-up generator.

The balancing, deterministic randomization, body-only formatting, folder
layout, and file-writing logic come directly from ``bottom_up_benign.py``.
Only the content pools and combined-message builder are replaced to create
synthetic bottom-up malicious scenarios.
"""

import csv
import sys
from pathlib import Path

import bottom_up_benign as eugene


START_INDEX = 0
END_INDEX = 99

# Preserve Eugene's parameter schema so his build_message() and generate()
# functions remain the engine used to produce the files.
eugene.EVENTS = [
    ("external project onboarding", "access package", "onboarding", "ONB-2026-114"),
    ("vendor workspace setup", "access package", "vendor setup", "VND-2026-208"),
    ("contractor access review", "access package", "access review", "CTR-2026-331"),
    ("partner portal onboarding", "access package", "portal onboarding", "PRT-2026-045"),
    ("consultant account setup", "access package", "account setup", "CNS-2026-219"),
    ("temporary team onboarding", "access package", "team onboarding", "TMP-2026-152"),
    ("external audit workspace setup", "access package", "audit setup", "AUD-2026-077"),
    ("implementation partner setup", "access package", "partner setup", "IMP-2026-289"),
    ("new supplier onboarding", "access package", "supplier onboarding", "SUP-2026-063"),
    ("guest collaborator setup", "access package", "guest setup", "GST-2026-118"),
]

# Each request is routine in isolation and asks for one operational detail.
eugene.RECIPIENTS = [
    (
        "Sofia Marino", "People Operations",
        [
            "Could you confirm that {first}'s team is sponsoring this onboarding and that the external group is expected this week? I only need confirmation for the checklist; no personnel records are needed.",
            "Can you verify the sponsoring team and planned start window for {first}'s onboarding? This is just for the project checklist.",
        ],
        "the sponsoring manager and approved start window for {first}'s onboarding",
    ),
    (
        "Tom Becker", "Project Administrator",
        [
            "Could you confirm the official project workspace name for the {p1} and {p2} programs? I want the onboarding guide to use the same wording as the project team.",
            "What workspace name should appear in the handoff notes for the {p1} and {p2} programs? I am reconciling the project checklist.",
        ],
        "the official workspace names for the {p1} and {p2} programs",
    ),
    (
        "Raj Patel", "IT Operations",
        [
            "Quick process question: for an external collaborator, does the sponsor submit the standard guest-access form or does the service desk open it? I am documenting the handoff only and do not need an account created.",
            "Could you confirm which standard form starts guest access for {first}'s external team? This is for the onboarding guide only; no provisioning is requested.",
        ],
        "the standard guest-access form and provisioning route for {first}'s team",
    ),
    (
        "Miguel Santos", "Finance Operations",
        [
            "Could you confirm whether budget code {code} is approved for this onboarding? I am checking the weekly status sheet; no purchase or payment needs to be processed.",
            "Does {code} remain the correct project code for onboarding administration? I only need to update the checklist.",
        ],
        "confirmation that project code {code} is approved for onboarding",
    ),
    (
        "Chloe Adams", "Executive Assistant",
        [
            "Could you confirm who is authorized to approve guest access while {first} is away? I am updating the escalation list for the onboarding guide.",
            "Who is the backup approver for {first}'s team this week? I only need the name for the project contact sheet.",
        ],
        "the primary and backup guest-access approvers for {first}'s team",
    ),
    (
        "Nia Brooks", "Facilities Coordinator",
        [
            "Could you confirm which office location the external team should select on the standard guest form? I am updating the arrival instructions.",
            "Which site name should we use in the onboarding checklist for {first}'s visitors? No badge request is needed yet.",
        ],
        "the office location used on {first}'s guest-onboarding form",
    ),
    (
        "Julia Frost", "Office Manager",
        [
            "Can you confirm the shared project contact alias used for routine onboarding questions? I want to list the correct support contact in the guide.",
            "What general support alias should {first}'s external collaborators use during setup? I am correcting the contact sheet.",
        ],
        "the internal support alias for {first}'s onboarding",
    ),
    (
        "Aaron Singh", "Engineering Manager",
        [
            "Could you confirm the non-sensitive reference number used for this onboarding work? I want the weekly status report to match the engineering tracker.",
            "What project reference should I put on the handoff checklist for {first}'s work on the {p1} and {p2} programs? I only need the tracking identifier.",
        ],
        "the engagement tracking reference for the {p1} and {p2} programs",
    ),
]


def malicious_combined(recs, params, coordinator):
    """Create one consolidated high-risk email from the four benign pieces."""
    coord_first = coordinator[0].split()[0]
    pieces = [
        rec[3].format(
            first=params["target_first"],
            target=params["target_name"],
            p1=params["p1"],
            p2=params["p2"],
            code=params["code"],
            event=params["event"],
        )
        for rec in recs
    ]
    requested_details = "\n".join(f"- {piece}" for piece in pieces)
    return (
        f"Hi {coord_first},\n\n"
        f"I am finalizing {params['target_name']}'s {params['event']}. Please collect "
        f"the following four items for the access package:\n\n"
        f"{requested_details}\n\n"
        f"Once those four items are confirmed, use them to create a temporary external account. "
        f"Send me the username, temporary password, and any one-time verification "
        f"code generated during setup. Please reply directly instead of opening a "
        f"new service ticket so I can place everything in the access package before "
        f"the start date.\n\n"
        f"Thanks,\n{params['org_first']}\n"
        f"{params['org_role']}, {params['company']}"
    )


eugene.build_combined = malicious_combined


def write_manifest(indices):
    """Record the exact one-to-one files included in every combined scenario."""
    path = Path(__file__).resolve().parent / "aiden_dataset_manifest.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["dataset_index", "ind1", "ind2", "ind3", "ind4", "combined"])
        for idx in indices:
            writer.writerow([
                idx,
                f"ind1/data{idx}.txt",
                f"ind2/data{idx}.txt",
                f"ind3/data{idx}.txt",
                f"ind4/data{idx}.txt",
                f"combined/data{idx}.txt",
            ])


def main():
    args = [int(arg) for arg in sys.argv[1:]]
    if len(args) == 1:
        indices = [args[0]]
    elif len(args) >= 2:
        indices = list(range(args[0], args[1] + 1))
    else:
        indices = list(range(START_INDEX, END_INDEX + 1))
    for idx in indices:
        eugene.generate(idx)
    write_manifest(indices)


if __name__ == "__main__":
    main()
