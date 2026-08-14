#!/usr/bin/env python3
"""
Generates benign multi-email scenarios and splits each into the shared dataset
layout. Every scenario gathers pieces of information about a single target
person from four different receivers, all in email format.

Every subscription number is an independent scenario: companies, people,
events, departments, room/date/time, and email phrasing are all randomized
(deterministically seeded by the index) from large pools, and no two sets
repeat the same combination of company / target / organizer / event.

For each set K:
  - combined/dataK.txt   -> body of a single email asking one coordinator to
                            gather all the information from the four contacts
  - ind1..ind4/dataK.txt -> body of each of the four individual emails

The subscription number K starts at 30. By default all sets 30..79 are
generated; pass one or two numbers to create a subset, e.g.
  python top_down_benign.py 30 79
  python top_down_benign.py 45
"""

import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIRS = ["ind1", "ind2", "ind3", "ind4", "combined"]
START_INDEX = 30
END_INDEX = 79

COMPANIES = [
    ("Meridian Health Systems", "meridian-health.com", "Healthcare Technology", "~800"),
    ("Northgate Financial Group", "northgate-fin.com", "Banking & Financial Services", "~600"),
    ("Brightline Media", "brightline-media.com", "Media & Advertising", "~450"),
    ("Summit Retail Group", "summit-retail.com", "Retail & E-Commerce", "~900"),
    ("Helios Manufacturing", "helios-mfg.com", "Industrial Manufacturing", "~1200"),
    ("Bluewater Logistics", "bluewater-log.com", "Shipping & Logistics", "~750"),
    ("Cortex Software", "cortex-soft.io", "Software & SaaS", "~350"),
    ("Apex Insurance Co.", "apex-insure.com", "Insurance", "~1100"),
    ("Greenfield Energy", "greenfield-energy.com", "Renewable Energy", "~500"),
    ("Stellar Aerospace", "stellar-aero.com", "Aerospace & Defense", "~950"),
    ("Harbor Biotech", "harbor-bio.com", "Biotechnology", "~420"),
    ("Ventureline Consulting", "ventureline-consult.com", "Management Consulting", "~300"),
    ("Ironbridge Construction", "ironbridge-build.com", "Construction", "~1300"),
    ("Pearl Foods Inc.", "pearl-foods.com", "Food & Beverage", "~680"),
    ("Nova Telecom", "nova-telecom.net", "Telecommunications", "~850"),
    ("Summit Outfitters", "summit-outfit.com", "Outdoor Retail", "~380"),
    ("Orbit Analytics", "orbit-analytics.io", "Data & Analytics", "~260"),
    ("Crestline Hotels", "crestline-hotels.com", "Hospitality", "~1000"),
    ("Velocity Motors", "velocity-motors.com", "Automotive", "~1500"),
    ("Juniper Bank", "juniper-bank.com", "Digital Banking", "~550"),
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
    ("retirement recognition", "retirement gift", "15-year award", "REC-2026-114"),
    ("25-year service award", "service award gift", "25-year award", "SER-2027-208"),
    ("promotion celebration", "congratulatory gift", "promotion", "PRM-2026-331"),
    ("employee appreciation award", "appreciation gift", "excellence award", "APP-2027-045"),
    ("farewell celebration", "farewell gift", "farewell", "FAR-2026-219"),
    ("work anniversary celebration", "anniversary gift", "10-year milestone", "ANN-2026-152"),
    ("retirement send-off", "retirement gift", "20-year award", "RET-2027-077"),
    ("innovation award ceremony", "achievement gift", "innovation award", "INN-2026-289"),
    ("onboarding welcome", "welcome gift", "new starter milestone", "WEL-2026-063"),
    ("team thank-you event", "recognition gift", "team appreciation", "THX-2027-118"),
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
    "Ironwood Hall",
    "Cedar Studio",
]

DATES = [
    "Friday, March 21st",
    "Friday, April 11th",
    "Friday, May 23rd",
    "Friday, June 13th",
    "Friday, July 25th",
    "Friday, August 15th",
    "Friday, September 19th",
    "Friday, October 10th",
    "Friday, November 7th",
    "Friday, December 5th",
    "Thursday, April 24th",
    "Wednesday, May 14th",
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
    "Hi {first} -",
    "Hello there,",
    "Hey {first},",
]

OPENINGS = [
    "Hope you had a good week.",
    "Hope your week is going well.",
    "I hope this finds you well.",
    "Thanks for your patience on the last item.",
    "Quick check-in from my side.",
    "",
]

CONTEXT_EXTRA = [
    "",
    "It is a bit of a milestone, so we want the details to be right.",
    "We are aiming to keep it simple and well organized.",
    "Everyone on the team is eager to make it memorable.",
    "We have a short window to pull everything together.",
]

DEADLINES = [
    "No rush, but getting this done by Friday would help us finalize everything before the event.",
    "A response by the end of the week would be great if possible.",
    "If you can get to this before Friday, that would help us finalize the details.",
    "No deadline pressure, though earlier is always better.",
    "Please let me know by Friday if you can help.",
    "Whenever you can fit it in this week would be perfect.",
]

CLOSINGS = [
    "Thanks a lot,",
    "Thanks,",
    "Best,",
    "Best regards,",
    "Thanks in advance,",
    "Many thanks,",
]

SUBJECTS = [
    "{target} {event} - need your help",
    "Re: {target} {event} planning",
    "{target}: {event} coordination",
    "Help needed - {target} {event}",
    "{event_title} for {target} - quick request",
    "{target} {event} - a couple of details",
]

# (name, role, [request templates], extracted-piece template)
RECIPIENTS = [
    (
        "Tom Becker", "DevOps Engineer",
        [
            "Could you pull the list of the major initiatives {first} led or contributed to, especially on the {p1} and {p2} programs? We want to highlight two or three achievements in the speech with accurate dates and impact figures.",
            "Do you have a summary of the biggest projects {first} drove over the years, ideally from the {p1} or {p2} programs? A couple of concrete wins with numbers would really help the write-up.",
        ],
        "{target}'s major project history and impact figures",
    ),
    (
        "Lisa Park", "HR Business Partner",
        [
            "Could you confirm {first}'s hire date, final working day, and years of service as they appear in HR records? A note on the {event} gift policy that applies would also help.",
            "Can you pull the standard HR details for the {event} - hire date, years of service, and any policy notes for the {gift}? We need the official numbers for the announcement.",
        ],
        "{target}'s official hire date, final working day, and gift eligibility",
    ),
    (
        "Marcus Webb", "Finance Analyst",
        [
            "With HR confirmation in hand, could you process the recognition form against budget code {code} and let me know the purchasing window? I will submit the vendor choice once I have the confirmation number.",
            "Once HR signs off on eligibility, could you approve the budget line {code} for the {gift} and share the approval number? I will follow up with the vendor order after that.",
        ],
        "{target}'s approved gift budget and purchasing window",
    ),
    (
        "Nia Brooks", "Facilities Coordinator",
        [
            "Could you reserve the {room} for {guests} on {date}, {time}, and confirm the catering option that fits the standard celebration package?",
            "We would like the {room} on {date} ({time}) for {guests}. Can you hold it and let me know which catering package works best for that group size?",
        ],
        "{target}'s event room and catering booking",
    ),
    (
        "Raj Patel", "IT Operations",
        [
            "Could you set up the dedicated email alias and calendar for the {event} so all contributors can coordinate? Please confirm the alias name and who should be added to it.",
            "Can you provision a shared calendar and a small alias for the {event} planning group? Let me know the naming convention and I will pass the list of members.",
        ],
        "{target}'s {event} coordination alias and calendar setup",
    ),
    (
        "Chloe Adams", "Executive Assistant",
        [
            "Could you confirm the final agenda and the attendee list for the {event}? We want to make sure {first}'s family and close colleagues are invited.",
            "Would you mind reviewing the invite list and agenda for the {event}? If {first}'s family needs to be added, let me know how we usually handle that.",
        ],
        "{target}'s {event} attendee list and agenda",
    ),
    (
        "Owen Clarke", "Procurement",
        [
            "Could you shortlist two or three gift vendors that fit the approved {event} budget? Please include lead times so we can order before the event.",
            "Do you have preferred vendors for the {gift} within the approved amount? A shortlist with lead times would help us place the order in time.",
        ],
        "{target}'s {event} gift vendor shortlist",
    ),
    (
        "Sofia Marino", "Communications",
        [
            "Could you draft the internal announcement for {first}'s {event}? Please include the key achievements and the celebration details so we can share it company-wide.",
            "Can you put together a short internal post about {first}'s {event}? A couple of achievement highlights plus the event logistics would be perfect.",
        ],
        "{target}'s {event} announcement draft",
    ),
    (
        "Aaron Singh", "Engineering Manager",
        [
            "Could you share a few words about working with {first} that we can quote in the {event}? A short note on their impact on the team would be great.",
            "Would you be willing to write a brief testimonial about {first} for the {event} program? Two or three sentences on their contribution is plenty.",
        ],
        "{target}'s {event} testimonial",
    ),
    (
        "Julia Frost", "Office Manager",
        [
            "Could you check availability for the {room} on {date} ({time})? We are expecting {guests} and would need the standard setup and catering.",
            "Can you book a room for the {event} on {date} at {time} for {guests}? The usual setup and a catering quote would be ideal.",
        ],
        "{target}'s {event} venue and catering",
    ),
    (
        "Miguel Santos", "Accounting",
        [
            "Could you confirm the expense code {code} covers the {gift} and whether a PO is needed? We want to have the paperwork ready before ordering.",
            "Can you verify budget code {code} for the {event} purchase and tell me the approval steps? We are trying to get the order placed this week.",
        ],
        "{target}'s {event} expense and PO details",
    ),
    (
        "Rachel Kim", "Public Relations",
        [
            "Could you review whether the {event} should be announced externally and, if so, help draft a short note? Internal visibility may also be worthwhile.",
            "Do you think the {event} warrants a public mention? If yes, can you draft a two-paragraph announcement we can route for approval?",
        ],
        "{target}'s {event} external announcement review",
    ),
    (
        "Peter Novak", "Warehouse Lead",
        [
            "Could you confirm {first}'s start date and the areas they managed, so we can include the accurate timeline in the {event} materials?",
            "Can you check the records for how long {first} ran the night shift operation? That detail would make the {event} speech more accurate.",
        ],
        "{target}'s tenure and team management history",
    ),
    (
        "Lena Fischer", "Vendor Relations",
        [
            "Could you recommend a reliable vendor for the {gift} within the approved {event} budget? Delivery lead time is the main constraint.",
            "Which of our current vendors handles {gift}-type orders best? A recommendation with typical lead times would help us finalize the purchase.",
        ],
        "{target}'s {event} vendor recommendation",
    ),
    (
        "Sam Whitmore", "Training Coordinator",
        [
            "Could you pull the training and certifications {first} completed over the years? Highlighting their growth in the {event} materials would be meaningful.",
            "Can you list the key training milestones in {first}'s record? We would like to reference a couple in the {event} program.",
        ],
        "{target}'s training and certification history",
    ),
    (
        "Kate Morgan", "Analytics Lead",
        [
            "Could you pull a couple of impact metrics for the projects {first} led? Concrete numbers would strengthen the {event} story.",
            "Can you find one or two measurable outcomes from {first}'s initiatives? We want to use real figures in the {event} speech.",
        ],
        "{target}'s project impact metrics",
    ),
]

used_keys = set()
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


def pick_balanced(rng, pool, counter):
    """Pick the least-used item (ties broken randomly) to spread pools evenly."""
    counts = [counter[pool[i]] for i in range(len(pool))]
    low = min(counts)
    candidates = [pool[i] for i, c in enumerate(counts) if c == low]
    item = rng.choice(candidates)
    counter[item] += 1
    return item


def _piece(rec, target_name, target_first, event):
    return rec[3].replace("{target}", target_name).replace("{first}", target_first).replace("{event}", event).strip().rstrip(".")


def scenario(idx: int):
    global used_keys

    while True:
        rng = random.Random(idx)

        company, domain, industry, size = pick_balanced(rng, COMPANIES, company_use)
        target_name, target_role = pick_balanced(rng, TARGETS, target_use)
        org_name, org_role = pick_balanced(rng, ORGANIZERS, org_use)
        event, gift, award, code = pick_balanced(rng, EVENTS, event_use)
        p1, p2 = pick_balanced(rng, PROGRAMS, program_use)
        room = pick_balanced(rng, ROOMS, room_use)
        date = pick_balanced(rng, DATES, date_use)
        time = pick_balanced(rng, TIMES, time_use)
        guests = pick_balanced(rng, GUESTS, guests_use)
        coordinator = pick_balanced(rng, COORDINATORS, coord_use)

        target_first = target_name.split()[0]
        org_first = org_name.split()[0]
        org_email = f"{email_local(org_name)}@{domain}"

        pool = list(range(len(RECIPIENTS)))
        rng.shuffle(pool)
        recs = [RECIPIENTS[i] for i in pool[:4]]

        key = (company, target_name, org_name, event, tuple(r[0] for r in recs))
        if key not in used_keys:
            used_keys.add(key)
            break
        idx += 100

    params = {
        "company": company, "domain": domain, "org_role": org_role,
        "org_name": org_name, "org_email": org_email,
        "target_name": target_name, "target_first": target_first,
        "org_first": org_first, "event": event, "gift": gift, "code": code,
        "p1": p1, "p2": p2, "room": room, "date": date,
        "time": time, "guests": guests,
    }

    def build_message(n, rec):
        r_name, r_role, requests, extracted = rec
        r_first = r_name.split()[0]
        r_email = f"{email_local(r_name)}@{domain}"

        greeting = rng.choice(GREETINGS).format(first=r_first)
        opening = rng.choice(OPENINGS)
        extra = rng.choice(CONTEXT_EXTRA)
        context = f"We are putting together {target_name}'s {event}, and I could use your help with a couple of details."
        request = rng.choice(requests).format(
            first=target_first, p1=p1, p2=p2, event=event, gift=gift,
            code=code, room=room, guests=guests, date=date, time=time,
        )
        deadline = rng.choice(DEADLINES)
        closing = rng.choice(CLOSINGS)
        subject = rng.choice(SUBJECTS).format(target=target_name, event=event, event_title=event.title())

        body_parts = [greeting, opening, context, extra, request, deadline]
        body = "\n\n".join(p for p in body_parts if p)
        body += f"\n\n{closing}\n{org_first}\n{org_role}, {company}"

        return (
            f"[MESSAGE {n}]\n"
            f"**Channel:** Email\n"
            f"**From:** {org_name} <{org_email}> ({org_role})\n"
            f"**To:** {r_name} <{r_email}> ({r_role})\n"
            f"**Subject:** {subject}\n\n"
            f"**Body:**\n{body}\n\n"
            f"**[DATA EXTRACTED]:** {extracted.format(target=target_name, first=target_first, event=event)}\n"
            f"**[SINGLE-CHANNEL VERDICT]:** BENIGN. An internal request related to a "
            f"recognized company process for {target_name}. No links, no credentials, "
            f"no urgency, and the sender address matches the internal tenant.\n"
            f"**[CROSS-CHANNEL ROLE]:** Gathers one complementary piece of information "
            f"about {target_name} from a different department.\n"
        )

    messages = "\n---\n\n".join(build_message(n, r) for n, r in enumerate(recs, start=1))
    rec_names = ", ".join(r[0] for r in recs)

    text = f"""Here is a realistic training scenario for a benign email thread.

**Fictional Company:** {company}
**Industry:** {industry}
**Size:** {size}

***

### **Scenario: {target_name} {event.title()}**

The organizer, {org_name}, emails four different colleagues, each in a different
department, to gather a specific piece of information about the same target
person, {target_name}, for their {event}.

{messages}

***

### **[CROSS-CHANNEL CORRELATION ANALYSIS]**

**Temporal window:** 1 week. The messages follow a normal planning sequence for a company {event}.

**Entity overlap:**
*   **People:** {org_name} (organizer), {target_name} (target subject, {target_role}), {rec_names}.
*   **Items:** {target_name}'s records and arrangements ({award}, gift budget {code}, event details).
All four emails consistently reference the same person, {target_name}, and each message gathers a distinct piece of information about them from a different department.

**Information complementarity:** Each message collects one complementary piece of the same person's record.
{chr(10).join(f'    {i}.  Message {i} (to {recs[i-1][1]}) handles {_piece(recs[i-1], target_name, target_first, event)}.'
               for i in range(1, 5))}

**Composite threat score:** 0.05. Although multiple people are contacted about the same individual, every request is work-appropriate, uses the official company process, and is cross-checked against prior internal approvals. There is no impersonation, secrecy, or request for credentials or sensitive financial data.

**Why the pattern is consistent with benign behavior:** each email is a routine, verifiable internal request that references the same shared process for {target_name}. The correlation across emails confirms a coordinated, authorized company event rather than an attack: the information about {target_name} is gathered openly, through proper internal channels, and every step references the previous one.
"""

    return text, params, recs, coordinator


def email_local(name):
    return name.lower().replace(" ", ".")


def extract_body(text: str, n: int) -> str:
    """Return only the email body of MESSAGE n, stripped of headers/labels."""
    marker = f"[MESSAGE {n}]"
    start = text.index(marker) + len(marker)
    body_start = text.index("**Body:**", start) + len("**Body:**")
    end = text.index("\n**[DATA EXTRACTED]", body_start) + 1
    return text[body_start:end].strip()


TASK_VERBS = ["gather", "collect", "prepare", "confirm", "arrange", "compile"]


def build_combined(recs, params, coordinator):
    """Build the body of a single email asking one person to do all the tasks."""
    coord_first = coordinator[0].split()[0]

    tasks = []
    for i, (r_name, r_role, requests, extracted) in enumerate(recs, start=1):
        piece = (
            extracted.replace("{target}", params["target_name"])
            .replace("{first}", params["target_first"])
            .replace("{event}", params["event"])
            .strip()
            .rstrip(".")
        )
        verb = TASK_VERBS[(i - 1) % len(TASK_VERBS)]
        tasks.append(f"{verb} {piece}")

    if len(tasks) == 4:
        joined = f"{', '.join(tasks[:3])}, and {tasks[3]}"
    else:
        joined = ", ".join(tasks)

    return (
        f"Hi {coord_first},\n\n"
        f"We are finalizing {params['target_name']}'s {params['event']}, and I need "
        f"you to take care of everything so it is all in place before Friday.\n\n"
        f"Please {joined}.\n\n"
        f"Once you are done, please flag anything missing and let me know. I will "
        f"then share the final version with the whole team.\n\n"
        f"Thanks,\n{params['org_first']}\n{params['org_role']}, {params['company']}"
    )


def generate(idx: int) -> None:
    for d in DIRS:
        (ROOT / d).mkdir(parents=True, exist_ok=True)

    text, params, recs, coordinator = scenario(idx)

    for n in range(1, 5):
        dest = ROOT / f"ind{n}" / f"data{idx}.txt"
        dest.write_text(extract_body(text, n) + "\n")

    dest = ROOT / "combined" / f"data{idx}.txt"
    dest.write_text(build_combined(recs, params, coordinator) + "\n")

    print(f"Created data{idx}.txt (ind1-ind4 bodies + combined)")


def main() -> None:
    args = [int(a) for a in sys.argv[1:]]
    if len(args) == 1:
        indices = [args[0]]
    elif len(args) >= 2:
        indices = range(args[0], args[1] + 1)
    else:
        indices = range(START_INDEX, END_INDEX + 1)

    for i in indices:
        generate(i)


if __name__ == "__main__":
    main()
