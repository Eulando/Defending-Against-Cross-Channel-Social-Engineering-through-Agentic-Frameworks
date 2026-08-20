#!/usr/bin/env python3
"""
Synthetic benign bottom-up multi-email dataset generator.

For each dataset K:

    ind1/dataK.txt
    ind2/dataK.txt
    ind3/dataK.txt
    ind4/dataK.txt

are generated first.

Then:

    combined/dataK.txt

is generated from all four individual emails.

Default range:
    0..99 inclusive

Examples:
    python bottom_up_benign.py
    python bottom_up_benign.py 25
    python bottom_up_benign.py 25 40

No API keys, network access, or third-party packages are required.
"""

import random
import sys
from collections import Counter
from pathlib import Path


# ============================================================================
# CONFIGURATION
# ============================================================================

ROOT = Path(__file__).resolve().parent

DIRS = [
    "ind1",
    "ind2",
    "ind3",
    "ind4",
    "combined",
]

START_INDEX = 0
END_INDEX = 99


# ============================================================================
# SYNTHETIC DATA POOLS
# ============================================================================

COMPANIES = [
    ("Meridian Health Systems", "Healthcare Technology"),
    ("Northgate Financial Group", "Banking & Financial Services"),
    ("Brightline Media", "Media & Advertising"),
    ("Summit Retail Group", "Retail & E-Commerce"),
    ("Helios Manufacturing", "Industrial Manufacturing"),
    ("Bluewater Logistics", "Shipping & Logistics"),
    ("Cortex Software", "Software & SaaS"),
    ("Apex Insurance Co.", "Insurance"),
    ("Greenfield Energy", "Renewable Energy"),
    ("Stellar Aerospace", "Aerospace"),
    ("Harbor Biotech", "Biotechnology"),
    ("Ventureline Consulting", "Management Consulting"),
    ("Ironbridge Construction", "Construction"),
    ("Pearl Foods Inc.", "Food & Beverage"),
    ("Nova Telecom", "Telecommunications"),
    ("Summit Outfitters", "Outdoor Retail"),
    ("Orbit Analytics", "Data & Analytics"),
    ("Crestline Hotels", "Hospitality"),
    ("Velocity Motors", "Automotive"),
    ("Juniper Bank", "Digital Banking"),
]

TARGETS = [
    ("Daniel Okafor", "Systems Architect"),
    ("Maya Thompson", "Finance Director"),
    ("James Whitfield", "Senior Software Engineer"),
    ("Elena Rodriguez", "Marketing Lead"),
    ("Samuel Osei", "Operations Manager"),
    ("Grace Nguyen", "Data Engineer"),
    ("Lucas Meyer", "Supply Chain Manager"),
    ("Fatima Hassan", "Quality Assurance Manager"),
    ("Robert Chen", "Engineering Manager"),
    ("Amara Diallo", "Product Designer"),
    ("Viktor Petrov", "Security Analyst"),
    ("Nina Kowalski", "Customer Success Director"),
    ("Theo Martin", "Sales Lead"),
    ("Priya Nair", "Research Scientist"),
    ("Carlos Mendez", "Warehouse Supervisor"),
    ("Ingrid Halvorsen", "Legal Counsel"),
    ("Omar Farouk", "Network Administrator"),
    ("Yuki Tanaka", "UX Researcher"),
    ("Beatrice Duval", "Compliance Officer"),
    ("Kenneth Brooks", "Facilities Manager"),
]

ORGANIZERS = [
    ("Priya Raman", "Clinical Product Manager"),
    ("Jordan Lee", "Program Manager"),
    ("Aisha Khan", "Operations Lead"),
    ("Marcus Cole", "Team Lead"),
    ("Hannah Liu", "Project Manager"),
    ("Daniel Reyes", "Delivery Manager"),
    ("Sofia Almeida", "People Operations Specialist"),
    ("Ethan Carter", "Office Manager"),
    ("Layla Haddad", "Culture & Events Coordinator"),
    ("Noah Williams", "Business Operations Manager"),
    ("Zara Iqbal", "Talent Program Manager"),
    ("Owen Davis", "Executive Assistant"),
    ("Mia Sullivan", "Marketing Operations Manager"),
    ("Gabriel Ortiz", "Finance Operations Analyst"),
    ("Emily Novak", "Project Coordinator"),
    ("Lucas Bianchi", "Internal Communications Lead"),
]

EVENTS = [
    ("retirement recognition", "retirement gift", "REC-2026-114"),
    ("service anniversary", "service award gift", "SER-2026-208"),
    ("promotion celebration", "congratulatory gift", "PRM-2026-331"),
    ("employee appreciation", "appreciation gift", "APP-2026-045"),
    ("farewell celebration", "farewell gift", "FAR-2026-219"),
    ("work anniversary", "anniversary gift", "ANN-2026-152"),
    ("innovation recognition", "achievement gift", "INN-2026-289"),
    ("onboarding welcome", "welcome gift", "WEL-2026-063"),
    ("team thank-you event", "recognition gift", "THX-2026-118"),
    ("milestone celebration", "milestone gift", "MIL-2026-077"),
]

PROGRAMS = [
    ("Atlas", "Aurora"),
    ("Helix", "Nexus"),
    ("Orion", "Vertex"),
    ("Pulse", "Spectrum"),
    ("Ion", "Forge"),
    ("Nova", "Quasar"),
    ("Summit", "Valley"),
    ("Beacon", "Crestline"),
    ("Falcon", "Meridian"),
    ("Horizon", "Zenith"),
]

ROOMS = [
    "East Conference Room",
    "Summit Boardroom",
    "Horizon Room",
    "Lakeside Terrace",
    "Oak Auditorium",
    "Maple Lounge",
    "Harbor View Room",
    "Atrium Stage",
    "Skyline Conference Room",
    "Garden Pavilion",
]

DATES = [
    "Friday, March 20th",
    "Friday, April 10th",
    "Friday, May 22nd",
    "Friday, June 12th",
    "Friday, July 24th",
    "Friday, August 14th",
    "Friday, September 18th",
    "Friday, October 9th",
    "Friday, November 6th",
    "Friday, December 4th",
]

TIMES = [
    "2:00-5:00 PM",
    "3:00-6:00 PM",
    "10:00 AM-1:00 PM",
    "4:00-7:00 PM",
    "12:00-3:00 PM",
    "1:30-4:30 PM",
    "9:00 AM-12:00 PM",
    "5:00-8:00 PM",
]

GUESTS = [
    "about 40 guests",
    "about 30 guests",
    "about 60 guests",
    "about 25 guests",
    "around 50 guests",
    "roughly 35 guests",
    "close to 45 guests",
    "up to 20 guests",
]

COORDINATORS = [
    ("Maria Gomez", "Event Coordinator"),
    ("David Lin", "Recognition Coordinator"),
    ("Sara Novak", "Program Coordinator"),
    ("Tom Alvarez", "Events Administrator"),
    ("Lena Ortiz", "Celebrations Coordinator"),
    ("Jack Morgan", "Operations Assistant"),
]

GREETINGS = [
    "Hi {first},",
    "Hello {first},",
    "Good morning {first},",
    "Hello there,",
    "Hey {first},",
]

OPENINGS = [
    "Hope you had a good week.",
    "Hope your week is going well.",
    "I hope this finds you well.",
    "Quick check-in from my side.",
    "",
]

DEADLINES = [
    "A response by the end of the week would be great if possible.",
    "If you can get to this before Friday, that would help us finalize the details.",
    "Whenever you can fit this in this week would be perfect.",
    "Getting this done by Friday would help us keep everything on schedule.",
]

CLOSINGS = [
    "Thanks a lot,",
    "Thanks,",
    "Best,",
    "Best regards,",
    "Many thanks,",
]


# ============================================================================
# INDIVIDUAL EMAIL TYPES
# ============================================================================

RECIPIENTS = [
    {
        "name": "Tom Becker",
        "role": "DevOps Engineer",
        "category": "project_history",
        "request": (
            "Could you share two or three major initiatives {first} "
            "worked on, particularly the {p1} and {p2} programs? "
            "A short description of their contribution would help "
            "with the recognition materials."
        ),
    },
    {
        "name": "Lisa Park",
        "role": "HR Business Partner",
        "category": "service_history",
        "request": (
            "Could you confirm {first}'s hire year and years of service "
            "for the recognition announcement? We want the timeline in "
            "the program to be accurate."
        ),
    },
    {
        "name": "Marcus Webb",
        "role": "Finance Analyst",
        "category": "budget",
        "request": (
            "Could you confirm the recognition budget associated with "
            "code {code} and the standard purchasing window for the "
            "{gift}? This will help us plan the order."
        ),
    },
    {
        "name": "Nia Brooks",
        "role": "Facilities Coordinator",
        "category": "venue",
        "request": (
            "Could you reserve the {room} for {guests} on {date}, "
            "{time}, and confirm the standard catering option?"
        ),
    },
    {
        "name": "Raj Patel",
        "role": "IT Operations",
        "category": "coordination",
        "request": (
            "Could you set up the shared calendar for the {event} "
            "planning group and confirm the calendar name?"
        ),
    },
    {
        "name": "Chloe Adams",
        "role": "Executive Assistant",
        "category": "agenda",
        "request": (
            "Could you confirm the draft agenda and attendee count "
            "for the {event}? We want the program materials to be "
            "consistent."
        ),
    },
    {
        "name": "Owen Clarke",
        "role": "Procurement",
        "category": "vendor",
        "request": (
            "Could you suggest two or three approved vendors for the "
            "{gift}, including their typical delivery times?"
        ),
    },
    {
        "name": "Sofia Marino",
        "role": "Communications",
        "category": "announcement",
        "request": (
            "Could you draft a short internal announcement for "
            "{first}'s {event}, including the key achievement "
            "highlights?"
        ),
    },
    {
        "name": "Aaron Singh",
        "role": "Engineering Manager",
        "category": "testimonial",
        "request": (
            "Could you share two or three sentences about {first}'s "
            "contribution to the team that we could use in the "
            "recognition program?"
        ),
    },
    {
        "name": "Julia Frost",
        "role": "Office Manager",
        "category": "logistics",
        "request": (
            "Could you check availability for the {room} on {date} "
            "at {time} for {guests}, including the standard room setup?"
        ),
    },
    {
        "name": "Miguel Santos",
        "role": "Accounting",
        "category": "expense",
        "request": (
            "Could you confirm whether expense code {code} can be used "
            "for the {gift} and whether the normal approval process "
            "requires a purchase order?"
        ),
    },
    {
        "name": "Sam Whitmore",
        "role": "Training Coordinator",
        "category": "training",
        "request": (
            "Could you list a few training milestones {first} completed "
            "that would be appropriate to mention in the recognition "
            "materials?"
        ),
    },
    {
        "name": "Kate Morgan",
        "role": "Analytics Lead",
        "category": "metrics",
        "request": (
            "Could you provide one or two measurable outcomes from "
            "{first}'s work on the {p1} or {p2} programs?"
        ),
    },
    {
        "name": "Peter Novak",
        "role": "Operations Lead",
        "category": "team_history",
        "request": (
            "Could you summarize the teams or operational areas "
            "{first} has worked with over the years? A short timeline "
            "would be useful."
        ),
    },
    {
        "name": "Lena Fischer",
        "role": "Vendor Relations",
        "category": "vendor_recommendation",
        "request": (
            "Could you recommend an approved vendor for the {gift} "
            "and provide the typical delivery timeframe?"
        ),
    },
]


# ============================================================================
# BALANCING COUNTERS
# ============================================================================

company_use = Counter()
target_use = Counter()
org_use = Counter()
event_use = Counter()
program_use = Counter()
room_use = Counter()
date_use = Counter()
time_use = Counter()
guests_use = Counter()
coord_use = Counter()


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def ensure_directories():
    for directory in DIRS:
        (ROOT / directory).mkdir(
            parents=True,
            exist_ok=True,
        )


def pick_balanced(rng, pool, counter):
    if not pool:
        raise ValueError("Cannot choose from an empty pool.")

    lowest = min(counter[item] for item in pool)

    candidates = [
        item
        for item in pool
        if counter[item] == lowest
    ]

    selected = rng.choice(candidates)
    counter[selected] += 1

    return selected


def write_verified(path, text):
    if text is None:
        raise RuntimeError(
            f"Refusing to write None to {path}"
        )

    if not isinstance(text, str):
        raise RuntimeError(
            f"Expected string content for {path}"
        )

    if not text.strip():
        raise RuntimeError(
            f"Refusing to write empty file: {path}"
        )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        text.rstrip() + "\n",
        encoding="utf-8",
    )

    if not path.exists():
        raise RuntimeError(
            f"File was not created: {path}"
        )

    if path.stat().st_size == 0:
        raise RuntimeError(
            f"File was created empty: {path}"
        )

    saved = path.read_text(
        encoding="utf-8"
    )

    if not saved.strip():
        raise RuntimeError(
            f"File was written but contains no usable text: {path}"
        )


# ============================================================================
# SYNTHETIC INFORMATION
# ============================================================================

def generate_information(category, params, rng):
    first = params["target_first"]

    if category == "project_history":
        project = rng.choice([
            params["p1"],
            params["p2"],
        ])

        return (
            f"{first} contributed to the {project} program, "
            "with a focus on project coordination and delivery."
        )

    if category == "service_history":
        hire_year = rng.choice([
            2012,
            2013,
            2014,
            2015,
            2016,
        ])

        years = 2026 - hire_year

        return (
            f"{first}'s synthetic HR timeline lists a hire year of "
            f"{hire_year}, representing {years} years of service."
        )

    if category == "budget":
        amount = rng.choice([
            "$350",
            "$500",
            "$750",
            "$1,000",
            "$1,250",
        ])

        return (
            f"The synthetic recognition budget associated with "
            f"{params['code']} is {amount}."
        )

    if category == "venue":
        return (
            f"The synthetic event location is {params['room']} on "
            f"{params['date']} from {params['time']} for "
            f"{params['guests']}."
        )

    if category == "coordination":
        calendar_name = (
            f"{params['target_first']}-{params['event']}"
            .replace(" ", "-")
        )

        return (
            f"The shared synthetic planning calendar is named "
            f"{calendar_name}."
        )

    if category == "agenda":
        return (
            "The draft agenda includes welcome remarks, an achievement "
            "highlight, recognition remarks, and closing thanks. "
            f"The synthetic attendee count is {params['guests']}."
        )

    if category == "vendor":
        vendor = rng.choice([
            "Northstar Events",
            "Pine & Oak Supply",
            "Harbor Office Services",
            "Cedarline Gifts",
        ])

        return (
            f"An approved synthetic vendor option is {vendor}, "
            "with an estimated delivery window of 5-7 business days."
        )

    if category == "announcement":
        return (
            f"The synthetic announcement should highlight {first}'s "
            f"contribution to the {params['p1']} program and the "
            f"upcoming {params['event']}."
        )

    if category == "testimonial":
        return (
            f"A synthetic testimonial describes {first} as a dependable "
            "collaborator who helped the team deliver several "
            "cross-functional projects."
        )

    if category == "logistics":
        return (
            f"The synthetic logistics check lists {params['room']} as "
            "the preferred room, with standard seating and catering "
            f"for {params['guests']}."
        )

    if category == "expense":
        return (
            f"The synthetic purchasing note says code {params['code']} "
            f"is suitable for the {params['gift']} and follows the "
            "standard internal approval process."
        )

    if category == "training":
        course = rng.choice([
            "Project Leadership",
            "Advanced Analytics",
            "Team Facilitation",
            "Product Planning",
            "Operational Excellence",
        ])

        return (
            f"{first} completed the synthetic {course} training "
            "milestone."
        )

    if category == "metrics":
        metric = rng.choice([
            "18%",
            "22%",
            "27%",
            "31%",
            "35%",
        ])

        return (
            f"A synthetic project metric attributes a {metric} "
            f"improvement to one of {first}'s initiatives."
        )

    if category == "team_history":
        team = rng.choice([
            "Platform Operations",
            "Customer Programs",
            "Engineering Delivery",
            "Business Systems",
            "Product Operations",
        ])

        return (
            f"The synthetic timeline places {first} with the "
            f"{team} team during a previous project period."
        )

    if category == "vendor_recommendation":
        vendor = rng.choice([
            "Cedarline Gifts",
            "Northstar Events",
            "Pine & Oak Supply",
            "Harbor Office Services",
        ])

        return (
            f"The recommended synthetic vendor is {vendor}, with a "
            "typical delivery time of 5-7 business days."
        )

    raise ValueError(
        f"Unknown information category: {category}"
    )


# ============================================================================
# INDIVIDUAL EMAIL
# ============================================================================

def build_individual_email(rng, recipient, params):
    recipient_name = recipient["name"]
    recipient_first = recipient_name.split()[0]

    greeting = rng.choice(
        GREETINGS
    ).format(
        first=recipient_first
    )

    opening = rng.choice(OPENINGS)

    context = (
        f"We are preparing {params['target_name']}'s "
        f"{params['event']}, and I could use your help with one detail."
    )

    request = recipient["request"].format(
        first=params["target_first"],
        p1=params["p1"],
        p2=params["p2"],
        event=params["event"],
        gift=params["gift"],
        code=params["code"],
        room=params["room"],
        guests=params["guests"],
        date=params["date"],
        time=params["time"],
    )

    information = generate_information(
        recipient["category"],
        params,
        rng,
    )

    deadline = rng.choice(DEADLINES)
    closing = rng.choice(CLOSINGS)

    signature = (
        f"{closing}\n"
        f"{params['org_first']}\n"
        f"{params['org_role']}, {params['company']}"
    )

    body_parts = [
        greeting,
        opening,
        context,
        request,
        information,
        deadline,
        signature,
    ]

    body = "\n\n".join(
        part
        for part in body_parts
        if part and part.strip()
    )

    if not body.strip():
        raise RuntimeError(
            f"Generated empty individual email for {recipient_name}"
        )

    return {
        "recipient": recipient_name,
        "role": recipient["role"],
        "category": recipient["category"],
        "request": request,
        "information": information,
        "body": body,
    }


# ============================================================================
# COMBINED EMAIL
# ============================================================================

def build_combined(individual_records, params, coordinator, rng):
    if len(individual_records) != 4:
        raise ValueError(
            "Combined email requires exactly four individual records."
        )

    coordinator_first = coordinator[0].split()[0]

    facts = [
        record["information"]
        for record in individual_records
    ]

    if any(
        not fact or not fact.strip()
        for fact in facts
    ):
        raise RuntimeError(
            "Cannot build combined email because one of the "
            "four source records has no information."
        )

    openings = [
        (
            f"I've pulled together the latest details on "
            f"{params['target_name']}'s {params['event']}."
        ),
        (
            f"I have the main pieces for {params['target_name']}'s "
            f"{params['event']} together now."
        ),
        (
            f"The planning details for {params['target_name']}'s "
            f"{params['event']} are coming together."
        ),
        (
            f"I've collected the current planning notes for "
            f"{params['target_name']}'s {params['event']}."
        ),
    ]

    transitions = [
        (
            "The background information is covered as well, and "
            "the remaining planning details line up with it."
        ),
        (
            "That gives us a good starting point, and the event "
            "details are lining up as well."
        ),
        (
            "Along with that, I have the remaining logistics and "
            "supporting details ready for the draft."
        ),
        (
            "The rest of the planning information fits with that "
            "and should be enough for the current version."
        ),
    ]

    endings = [
        (
            "Please give everything a quick review and let me know "
            "if anything needs to be corrected before we circulate "
            "the final version."
        ),
        (
            "Once you've had a chance to look it over, let me know "
            "if there are any gaps or updates we should make."
        ),
        (
            "This should give us a complete starting point for the "
            "final materials; please flag anything that needs attention."
        ),
        (
            "If everything looks right, we can use this as the basis "
            "for the final event materials."
        ),
    ]

    opening = rng.choice(openings)
    transition = rng.choice(transitions)
    ending = rng.choice(endings)

    paragraph_one = (
        f"{opening} "
        f"{facts[0]} "
        f"{facts[1]}"
    )

    paragraph_two = (
        f"{transition} "
        f"{facts[2]} "
        f"{facts[3]}"
    )

    body = (
        f"Hi {coordinator_first},\n\n"
        f"{paragraph_one}\n\n"
        f"{paragraph_two}\n\n"
        f"{ending}\n\n"
        f"Thanks,\n"
        f"{params['org_first']}\n"
        f"{params['org_role']}, {params['company']}"
    )

    if not body.strip():
        raise RuntimeError(
            "Combined email was generated empty."
        )

    return body


# ============================================================================
# COMBINED VALIDATION
# ============================================================================

def validate_combined(individual_records, combined_body):
    if len(individual_records) != 4:
        raise AssertionError(
            "Expected exactly four individual records."
        )

    if not combined_body.strip():
        raise AssertionError(
            "Combined email is empty."
        )

    for number, record in enumerate(
        individual_records,
        start=1,
    ):
        information = record["information"]

        if not information.strip():
            raise AssertionError(
                f"Individual record {number} has empty information."
            )

        if information not in combined_body:
            raise AssertionError(
                f"Combined email is missing information from "
                f"individual record {number}."
            )


# ============================================================================
# DATASET GENERATION
# ============================================================================

def generate(idx):
    ensure_directories()

    rng = random.Random(idx)

    company, industry = pick_balanced(
        rng,
        COMPANIES,
        company_use,
    )

    target_name, target_role = pick_balanced(
        rng,
        TARGETS,
        target_use,
    )

    organizer_name, organizer_role = pick_balanced(
        rng,
        ORGANIZERS,
        org_use,
    )

    event, gift, code = pick_balanced(
        rng,
        EVENTS,
        event_use,
    )

    p1, p2 = pick_balanced(
        rng,
        PROGRAMS,
        program_use,
    )

    room = pick_balanced(
        rng,
        ROOMS,
        room_use,
    )

    date = pick_balanced(
        rng,
        DATES,
        date_use,
    )

    time = pick_balanced(
        rng,
        TIMES,
        time_use,
    )

    guests = pick_balanced(
        rng,
        GUESTS,
        guests_use,
    )

    coordinator = pick_balanced(
        rng,
        COORDINATORS,
        coord_use,
    )

    params = {
        "company": company,
        "industry": industry,
        "target_name": target_name,
        "target_role": target_role,
        "target_first": target_name.split()[0],
        "org_name": organizer_name,
        "org_first": organizer_name.split()[0],
        "org_role": organizer_role,
        "event": event,
        "gift": gift,
        "code": code,
        "p1": p1,
        "p2": p2,
        "room": room,
        "date": date,
        "time": time,
        "guests": guests,
    }

    recipients = list(RECIPIENTS)
    rng.shuffle(recipients)

    selected_recipients = recipients[:4]

    if len(selected_recipients) != 4:
        raise RuntimeError(
            f"Could not select four recipients for dataset {idx}."
        )

    individual_records = []

    for recipient in selected_recipients:
        record = build_individual_email(
            rng,
            recipient,
            params,
        )

        if not record["body"].strip():
            raise RuntimeError(
                f"Dataset {idx}: generated an empty individual email."
            )

        individual_records.append(record)

    for number, record in enumerate(
        individual_records,
        start=1,
    ):
        destination = (
            ROOT
            / f"ind{number}"
            / f"data{idx}.txt"
        )

        write_verified(
            destination,
            record["body"],
        )

    combined_body = build_combined(
        individual_records,
        params,
        coordinator,
        rng,
    )

    validate_combined(
        individual_records,
        combined_body,
    )

    combined_destination = (
        ROOT
        / "combined"
        / f"data{idx}.txt"
    )

    write_verified(
        combined_destination,
        combined_body,
    )

    expected_files = [
        ROOT / "ind1" / f"data{idx}.txt",
        ROOT / "ind2" / f"data{idx}.txt",
        ROOT / "ind3" / f"data{idx}.txt",
        ROOT / "ind4" / f"data{idx}.txt",
        ROOT / "combined" / f"data{idx}.txt",
    ]

    for path in expected_files:
        if not path.exists():
            raise RuntimeError(
                f"Dataset {idx} is missing: {path}"
            )

        if path.stat().st_size == 0:
            raise RuntimeError(
                f"Dataset {idx} contains an empty file: {path}"
            )

    print(
        f"[OK] dataset {idx:03d} "
        f"-> ind1 ind2 ind3 ind4 combined"
    )


# ============================================================================
# COMMAND-LINE HANDLING
# ============================================================================

def get_indices():
    """
    Parse command-line arguments.

    No arguments:
        0..99

    One argument:
        that single dataset

    Two arguments:
        inclusive range
    """

    raw_args = sys.argv[1:]

    try:
        args = [
            int(value)
            for value in raw_args
        ]
    except ValueError:
        print(
            "Error: dataset numbers must be integers.",
            file=sys.stderr,
        )
        sys.exit(1)

    if len(args) == 0:
        return range(
            START_INDEX,
            END_INDEX + 1,
        )

    if len(args) == 1:
        if args[0] < 0:
            print(
                "Error: dataset number must be >= 0.",
                file=sys.stderr,
            )
            sys.exit(1)

        return [args[0]]

    start = args[0]
    end = args[1]

    if start < 0 or end < 0:
        print(
            "Error: dataset numbers must be >= 0.",
            file=sys.stderr,
        )
        sys.exit(1)

    if start > end:
        print(
            "Error: start number cannot be greater than end number.",
            file=sys.stderr,
        )
        sys.exit(1)

    return range(
        start,
        end + 1,
    )


# ============================================================================
# MAIN
# ============================================================================

def main():
    indices = get_indices()

    ensure_directories()

    total = 0

    for idx in indices:
        generate(idx)
        total += 1

    print()
    print(
        f"Finished successfully: {total} dataset(s) generated."
    )
    print(
        f"Output directory: {ROOT}"
    )


if __name__ == "__main__":
    main()