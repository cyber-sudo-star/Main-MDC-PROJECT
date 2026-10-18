import os
import io
import sys
import re
import json
import random
import sqlite3
from functools import wraps

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import jinja2
from flask import Flask, render_template, request, redirect, url_for, g, jsonify, session, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from database.db import get_db, close_db, init_db, ensure_tables
except (ImportError, ModuleNotFoundError):
    from db import get_db, close_db, init_db, ensure_tables

try:
    from ml_engine.risk_scorer import calculate_user_risk_profile
    from ml_engine.explainability import generate_explainable_feedback
except (ImportError, ModuleNotFoundError):
    from risk_scorer import calculate_user_risk_profile
    from explainability import generate_explainable_feedback

from analytics_engine import get_personal_analytics
from phishing_engine import get_all_phishing_scenarios, get_phishing_scenario_by_id, evaluate_phishing_attempt
from ctf_engine import get_all_ctf_challenges, get_ctf_challenge_by_id, validate_ctf_flag
from ai_analyst_engine import generate_structured_threat_report, generate_ai_threat_report
from war_room_engine import get_all_war_room_scenarios, start_or_get_war_room_session, get_war_room_session_state, record_war_room_decision
from skills_engine import calculate_user_skills, get_all_badges_with_user_status, issue_or_get_certificate, verify_certificate_by_id
from threat_intel_service import get_threat_intel_records, sync_threat_intel_feed
from admin_service import admin_required, get_admin_metrics, get_all_scenarios_admin, get_all_users_admin, toggle_scenario_status, toggle_user_role, export_training_report_csv
import functools
def login_required(f):
    @functools.wraps(f)
    def wrap(*args, **kwargs):
        return f(*args, **kwargs)
    return wrap
template_folders = [
    os.path.join(BASE_DIR, 'templates'),
    BASE_DIR,
    os.path.join(os.path.dirname(BASE_DIR), 'templates')
]

app = Flask(__name__, template_folder=template_folders[0])
@app.before_request
def make_public():
    from flask import session
    session['logged_in'] = True
    session['user_id'] = 1
app.jinja_loader = jinja2.ChoiceLoader([
    jinja2.FileSystemLoader(p) for p in template_folders if os.path.exists(p)
])
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(32).hex()

try:
    ensure_tables()
except Exception as e:
    print(f"Notice: Database initialization during module load: {e}")

app.teardown_appcontext(close_db)


@app.route('/static/<path:filename>')
def serve_static(filename):
    target = os.path.join(BASE_DIR, 'static', filename)
    if os.path.exists(target):
        return send_from_directory(os.path.join(BASE_DIR, 'static'), filename)
    base_file = os.path.basename(filename)
    if os.path.exists(os.path.join(BASE_DIR, base_file)):
        return send_from_directory(BASE_DIR, base_file)
    parent_static = os.path.join(os.path.dirname(BASE_DIR), 'static', filename)
    if os.path.exists(parent_static):
        return send_from_directory(os.path.dirname(BASE_DIR), 'static/' + filename)
    return "File not found", 404

BASELINE_SCENARIO_IDS = [1, 2, 3, 4, 5, 6, 7, 8]

# ----------------- AUTHENTICATION HELPERS ----------------- #

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please sign in to access the system.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_completed_drill_ids(user_id):
    """Retrieves list of scenario IDs completed by the logged-in user, synced with session."""
    db = get_db()
    rows = db.execute("SELECT scenario_id FROM user_attempts WHERE user_id = ?", (user_id,)).fetchall()
    db_ids = [r['scenario_id'] for r in rows]
    session_ids = session.get('completed_drills', [])
    merged = list(dict.fromkeys(db_ids + session_ids))
    session['completed_drills'] = merged
    return merged

def fetch_user_profile_data(user_id):
    db = get_db()
    profile = db.execute("SELECT * FROM user_profiles WHERE user_id = ?", (user_id,)).fetchone()
    if not profile:
        return {
            "composite_risk_score": 50.0,
            "primary_weakness": "Baseline (Not yet evaluated)",
            "category_stats": {},
            "total_tests": 0,
            "accuracy_pct": 0.0,
            "risk_level": "Unrated (Baseline)"
        }

    stats = json.loads(profile['category_stats']) if profile['category_stats'] else {}
    score = profile['composite_risk_score']
    if score < 30.0:
        risk_level = "Low Risk (Vigilant 🛡️)"
    elif score < 65.0:
        risk_level = "Moderate Risk (Cautious ⚠️)"
    else:
        risk_level = "High Risk (Vulnerable 🚨)"

    return {
        "composite_risk_score": score,
        "primary_weakness": profile['primary_weakness'],
        "category_stats": stats,
        "total_tests": profile['total_tests'],
        "accuracy_pct": profile['accuracy_pct'],
        "risk_level": risk_level
    }

def clean_scenario_title(title):
    if not title:
        return ""
    return re.sub(r'\s*(\[Ref\s*#\d+\]|\(Bulletin\s*#\d+\))', '', title).strip()

def fetch_user_attempts(user_id):
    db = get_db()
    rows = db.execute("""
        SELECT a.id, a.scenario_id, a.user_choice, a.is_correct, a.response_time_sec,
               strftime('%Y-%m-%d %H:%M', a.timestamp) as timestamp,
               s.title, s.category_code, s.is_threat, s.channel
        FROM user_attempts a
        JOIN scenarios s ON a.scenario_id = s.id
        WHERE a.user_id = ?
        ORDER BY a.id DESC
    """, (user_id,)).fetchall()

    attempts = []
    for r in rows:
        title = clean_scenario_title(r["title"])
        attempts.append({
            "id": r["id"],
            "scenario_id": r["scenario_id"],
            "user_choice": bool(r["user_choice"]),
            "is_correct": bool(r["is_correct"]),
            "response_time_sec": r["response_time_sec"],
            "timestamp": r["timestamp"],
            "title": title,
            "clean_title": title,
            "category_code": r["category_code"],
            "is_threat": bool(r["is_threat"]),
            "channel": r["channel"]
        })
    return attempts

def fetch_all_scenarios():
    db = get_db()
    rows = db.execute("SELECT * FROM scenarios").fetchall()
    scenarios = []
    for r in rows:
        title = clean_scenario_title(r["title"])
        scenarios.append({
            "id": r["id"],
            "category_code": r["category_code"],
            "channel": r["channel"],
            "title": title,
            "clean_title": title,
            "sender": r["sender"],
            "sender_name": r["sender_name"],
            "subject": r["subject"],
            "body": r["body"],
            "is_threat": bool(r["is_threat"]),
            "difficulty": r["difficulty"],
            "red_flags": json.loads(r["red_flags"]) if r["red_flags"] else [],
            "explanation": r["explanation"],
            "micro_lesson": r["micro_lesson"]
        })
    return scenarios

def get_scenario_by_id(scenario_id):
    db = get_db()
    r = db.execute("SELECT * FROM scenarios WHERE id = ?", (scenario_id,)).fetchone()
    if not r:
        return None
    title = clean_scenario_title(r["title"])
    return {
        "id": r["id"],
        "category_code": r["category_code"],
        "channel": r["channel"],
        "title": title,
        "clean_title": title,
        "sender": r["sender"],
        "sender_name": r["sender_name"],
        "subject": r["subject"],
        "body": r["body"],
        "is_threat": bool(r["is_threat"]),
        "difficulty": r["difficulty"],
        "red_flags": json.loads(r["red_flags"]) if r["red_flags"] else [],
        "explanation": r["explanation"],
        "micro_lesson": r["micro_lesson"]
    }

# ----------------- DYNAMIC SCENARIO GENERATOR ----------------- #

DYNAMIC_TEMPLATES = [
    # 1. THREAT: AUTHORITY IMPERSONATION
    {
        "category_code": "AUTHORITY",
        "is_threat": True,
        "difficulty": "medium",
        "channel": "email",
        "senders": [
            ("Office of the Dean", "dean-executive@campus-advisory.org"),
            ("Office of the Provost", "provost.office@faculty-board.org"),
            ("Campus Chief Information Officer", "cio-administrative@it-governance.org"),
            ("Vice Chancellor for Academic Affairs", "vice-chancellor@univ-administration.net")
        ],
        "titles": [
            "Executive Directive: Urgent Committee Discretionary Procurement",
            "Confidential Request from Academic Leadership",
            "Administrative Advisory: Off-Campus Delegation Honorarium"
        ],
        "subjects": [
            "CONFIDENTIAL: Urgent request regarding keynote symposium honorarium",
            "DISCREET: Need your immediate assistance before trustee meeting",
            "Action Required: Emergency departmental procurement requisition"
        ],
        "bodies": [
            "Hello,\n\nI am currently in an all-day executive board session with restricted mobile access. We have an unexpected keynote guest arriving shortly, and our department needs 4 Apple/Amazon digital gift cards ($100 each) for an honorarium package.\n\nPlease purchase these online immediately and email the scratch-off PIN codes directly to this address. I will sign your expense reimbursement voucher first thing tomorrow morning.\n\nTreat this with discretion and do not call my office line while the board session is active.\n\nWarm regards,\nOffice of Leadership",
            "Greetings,\n\nI am writing to request your prompt assistance on a confidential matter regarding visiting faculty accommodations. Standard purchasing channels are delayed, and we need you to process an immediate transaction today.\n\nPlease reply with your private mobile number so I can send the vendor procurement code securely.\n\nThank you for your prompt cooperation.\nExecutive Directorate"
        ],
        "red_flags": [
            "Executive impersonation using an unofficial third-party domain (@campus-advisory.org or @faculty-board.org).",
            "Urgent request to purchase untraceable digital gift cards or bypass standard purchasing workflows.",
            "Directive to avoid standard phone or in-person verification under pretext of an executive meeting."
        ],
        "explanation": "This attack utilizes Authority Impersonation (Business Email Compromise). Attackers exploit psychological deference to senior leadership to bypass financial controls and procure untraceable gift cards.",
        "micro_lesson": "Senior administrators never ask staff or students to purchase gift cards or send credentials via email. Always verify unexpected leadership requests through verified directory phone numbers."
    },
    # 2. THREAT: URGENCY & TIME PRESSURE
    {
        "category_code": "URGENCY",
        "is_threat": True,
        "difficulty": "hard",
        "channel": "email",
        "senders": [
            ("Cloud Infrastructure Operations", "storage-alert@campus-cloud-admin.xyz"),
            ("Identity & Access Services", "identity-verification@account-portal.live"),
            ("Campus Email Administration", "postmaster@mailbox-quarantine-server.top")
        ],
        "titles": [
            "Storage Quota Exceeded: Account Purge in 45 Minutes",
            "Immediate Action: University Directory Account Expiration",
            "Urgent: Two-Factor Authentication Termination Warning"
        ],
        "subjects": [
            "CRITICAL ALERT: Your university cloud storage is 99% full — purge scheduled",
            "FINAL WARNING: Student portal access expires in 45 minutes",
            "ACTION REQUIRED: Pending incoming messages held in quarantine"
        ],
        "bodies": [
            "Notice of Impending Data Deletion:\n\nYour institutional cloud storage account has reached 99.4% capacity (49.7 GB / 50 GB). System policies require automatic deletion of unverified profiles after 60 minutes.\n\nTo prevent permanent loss of your course documents, laboratory files, and mailbox access, you must validate your storage allocation immediately:\n\n➡️ Upgrade & Retain Storage: http://campus-cloud-admin.xyz/retain-quota?user=active\n\nFailure to act within the deadline will result in unrecoverable account wipe.",
            "Urgent Security Quarantine:\n\nSeven incoming academic messages addressed to you are currently held in central quarantine due to outdated directory certificates.\n\nYou have 30 minutes to release these documents before they are permanently purged from the server:\n\n🔗 Release Messages: http://mailbox-quarantine-server.top/release\n\nIT Support Operations"
        ],
        "red_flags": [
            "Artificial countdown deadline (30-45 minutes) engineered to trigger panic and hasty clicks.",
            "Suspicious top-level domain (.xyz or .top) masquerading as official campus cloud infrastructure.",
            "Severe threats of irreversible data loss or account termination."
        ],
        "explanation": "This attack targets the Urgency & Time Compression vector. By fabricating an impending countdown to data deletion, the attacker forces the victim to bypass logical evaluation.",
        "micro_lesson": "Official IT departments never wipe accounts with short countdown deadlines. Storage alerts can always be verified independently by navigating directly to the genuine university portal."
    },
    # 3. THREAT: INCENTIVE / REWARD TRAPS
    {
        "category_code": "INCENTIVE",
        "is_threat": True,
        "difficulty": "easy",
        "channel": "email",
        "senders": [
            ("Student Financial Grant Council", "grants@student-tech-endowment.info"),
            ("Campus Bookstore Rewards", "voucher-claims@bookstore-rewards-portal.org"),
            ("Academic Innovation Foundation", "awards@digital-scholarship-bursary.com")
        ],
        "titles": [
            "Selected for $350 Student Technology Equipment Grant",
            "Campus Bookstore Survey Bonus Voucher",
            "Unclaimed Research Technology Subsidy"
        ],
        "subjects": [
            "CONGRATULATIONS: You have been awarded a $350 Student Technology Grant",
            "CLAIM REWARD: $150 Campus Bookstore Digital Gift Card Selected",
            "Notice of Unclaimed Bursary: Direct Deposit Required"
        ],
        "bodies": [
            "Dear Student,\n\nWe are delighted to inform you that your registration ID was selected for the 2026 Academic Technology Subsidy ($350 Technology & Textbook Grant).\n\nNo repayment is required. Only 12 awards remain unallocated in your campus district.\n\nTo deposit the funds into your bank account, please claim your transfer token within 24 hours:\n\n💰 Claim Your Tech Grant: https://student-tech-endowment.info/claim?token=84912\n\nCongratulations from the Academic Endowment Panel!",
            "Campus Survey Incentive:\n\nThank you for being part of our campus community. You have been selected to receive a $150 digital reward card for completing a brief 2-minute student satisfaction survey.\n\n👉 Start Survey & Enter Deposit Info: http://bookstore-rewards-portal.org/survey\n\nFunds will be credited to your card upon completion."
        ],
        "red_flags": [
            "Unsolicited financial award for a program or lottery you never entered.",
            "Artificial scarcity claims ('Only 12 awards remain unallocated').",
            "External domain (.info or .org) requesting banking details for fund deposit."
        ],
        "explanation": "This scenario targets the Incentive & Greed bias. It exploits financial desire by dangling free money, causing victims to overlook blatant phishing hallmarks.",
        "micro_lesson": "If you did not apply for a grant, scholarship, or lottery, you did not win it. Legitimate financial aid is coordinated directly through the financial aid office on campus."
    },
    # 4. THREAT: COERCION & LEGAL THREATS
    {
        "category_code": "COERCION",
        "is_threat": True,
        "difficulty": "hard",
        "channel": "email",
        "senders": [
            ("Academic Integrity Board", "disciplinary@univ-judicial-case.net"),
            ("Campus Police & Parking Enforcement", "citations@campus-security-notice.com"),
            ("Copyright Compliance Bureau", "dmca-compliance@campus-network-audit.top")
        ],
        "titles": [
            "Academic Misconduct Allegation & Disciplinary Summons",
            "Campus Police Citation: Final Warrant Notice",
            "Network Copyright Infraction: Formal DMCA Notice"
        ],
        "subjects": [
            "FORMAL SUMMONS: Code plagiarism allegations in recent semester examination",
            "PARKING & SAFETY NOTICE: Delinquent citation warrant issued",
            "COPYRIGHT INFRINGEMENT: Illegal torrenting detected on your assigned IP"
        ],
        "bodies": [
            "CONFIDENTIAL JUDICIAL SUMMONS:\n\nA formal complaint has been filed with the Academic Honor Board alleging unauthorized code sharing and plagiarism in your laboratory assignment. If sustained, this carries mandatory academic probation.\n\nYou are required to download the evidence brief and case docket immediately to prepare your defense:\n\n📁 Download Case_Evidence_Brief.pdf.exe\n\nFailure to acknowledge receipt within 24 hours will result in automatic default findings without appeal.\n\nAcademic Honor Committee",
            "FINAL NOTICE BEFORE SUMMONS:\n\nOur records indicate an unresolved vehicular infraction on campus grounds with overdue fines totaling $240. Failure to clear this balance will result in an administrative hold on your registration and immediate vehicle towing.\n\nReview the infraction evidence report: http://campus-security-notice.com/case-docket\n\nCampus Security Bureau"
        ],
        "red_flags": [
            "Severe psychological intimidation and legal threats engineered to induce terror.",
            "Double extension executable file (.pdf.exe) masquerading as a document.",
            "Unrecognized third-party domain (@univ-judicial-case.net)."
        ],
        "explanation": "This attack utilizes Fear and Coercion. By threatening disciplinary action or legal consequences, the attacker induces panic so the target recklessly opens malware or submits credentials.",
        "micro_lesson": "Official university disciplinary notices are delivered via formal in-person or official student portal channels, never via unsolicited double-extension email attachments."
    },
    # 5. THREAT: FAKE VPN / PORTAL LINKS
    {
        "category_code": "FAKELINKS",
        "is_threat": True,
        "difficulty": "medium",
        "channel": "email",
        "senders": [
            ("IT Identity & Access Operations", "sso-migration@login-university-sso.xyz"),
            ("Campus Wi-Fi & Eduroam Desk", "eduroam-support@campus-network-auth.top"),
            ("Global Logistics Express", "notifications@fedx-parcel-track.live")
        ],
        "titles": [
            "Mandatory 2FA Duo Re-enrollment Required",
            "Campus Wi-Fi Certificate Security Upgrade",
            "Package Exception: Redelivery Fee Required"
        ],
        "subjects": [
            "ACTION REQUIRED: University Single Sign-On (SSO) 2FA Migration",
            "Network Alert: Update your Eduroam digital security certificate",
            "Courier Exception: Delivery address clarification needed (#TR-9941)"
        ],
        "bodies": [
            "University Central Authentication Notice:\n\nAs part of our semester cybersecurity upgrade, all students and employees must re-authenticate their Multi-Factor Authentication (MFA) devices on the new authentication gateway.\n\nFailure to complete re-enrollment today will lock your access to Blackboard, Canvas, and student email:\n\n🔐 Re-enroll Multi-Factor Device: http://login-university-sso.xyz/saml-verify\n\nIdentity & Access Services",
            "Delivery Exception Alert:\n\nYour courier parcel #TR-99412 cannot be delivered due to an unreadable apartment number. A minor redelivery postage fee ($1.75) is required to release the shipment from the local depot.\n\n📦 Update Address & Pay Fee: http://fedx-parcel-track.live/parcel\n\nGlobal Express Dispatch"
        ],
        "red_flags": [
            "Lookalike typosquatted domain (.xyz or .live) mimicking campus SSO or major couriers.",
            "Unsolicited request to input authentication credentials or credit card details.",
            "Urgency cues threatening immediate lockout if not re-enrolled."
        ],
        "explanation": "This attack utilizes Fake Links & Lookalike Domains. The attacker mimics an authentic institutional login screen to harvest passwords and session tokens.",
        "micro_lesson": "Always examine the full browser URL before typing credentials. Official university Single Sign-On (SSO) services always reside on verified .edu domains."
    },
    # 6. LEGITIMATE: OFFICIAL NOTICES & NEWSLETTERS
    {
        "category_code": "LEGITIMATE",
        "is_threat": False,
        "difficulty": "easy",
        "channel": "email",
        "senders": [
            ("University Central Library", "library-circulation@university.edu"),
            ("Office of the Registrar", "registrar-services@university.edu"),
            ("IT Infrastructure Services", "network-operations@university.edu"),
            ("Career & Internship Center", "career-development@university.edu"),
            ("Campus Health & Wellness", "student-health@university.edu")
        ],
        "titles": [
            "Scheduled Core Network Maintenance (Sunday 2:00 AM - 4:00 AM)",
            "Library Courtesy Reminder: Loan Renewal Notice",
            "Career Development: Tech Internship Fair Booth Directory",
            "Annual Free Campus Flu Vaccination Clinic Schedule",
            "Academic Calendar: Mid-Term Examination Schedule Released"
        ],
        "subjects": [
            "Informational: Scheduled Network Maintenance on Sunday Morning",
            "Courtesy Notice: Library books due for return or online renewal",
            "Upcoming Event: Annual Tech Internship Fair - Employer Roster",
            "Campus Wellness Announcement: Free Flu Clinic Dates at Student Center",
            "Academic Calendar Advisory: Fall Mid-Term Examination Timetable"
        ],
        "bodies": [
            "Campus Community Notice:\n\nIT Infrastructure Services will perform scheduled core switch firmware updates this Sunday between 2:00 AM and 4:00 AM. Intermittent wired and Wi-Fi connectivity drops may occur during this maintenance window.\n\nNo user action or password modification is required. Systems will return to standard operation by 4:30 AM.\n\nWarm regards,\nIT Network Operations",
            "Courtesy Library Notice:\n\nThis is a polite reminder that two items currently borrowed under your student card are due for renewal this coming Friday. You may return items in the 24/7 book drop outside the main library or review your loan status online.\n\nTo view your account, visit the library portal directly at https://library.university.edu.\n\nUniversity Library Services",
            "Dear Campus Trainee,\n\nWe are excited to announce that over 45 industry employers will attend the Annual Tech Career Fair on Thursday in the Student Recreation Hall. Please bring printed resumes and your campus ID card.\n\nRegistration is free and no advance reservations are needed. Details can be found at https://careers.university.edu.\n\nOffice of Career Development"
        ],
        "red_flags": [],
        "explanation": "This is a legitimate institutional communication. It originates from the authentic institution domain (@university.edu), uses standard professional tone, requests no confidential secrets or payments, and directs recipients to official .edu web properties.",
        "micro_lesson": "Legitimate institutional notices share operational information without urgent pressure, without asking for passwords, and without suspicious third-party links."
    }
]

def generate_dynamic_scenario():
    """
    Procedurally builds new scenario dictionaries in real time by randomly combining:
    a) Senders & Email Headers
    b) Attack Vectors & Types (Threats & Legitimate)
    c) Email Subject Lines & Realistic Body Content
    d) Ground Truth Flags
    e) Post-drill Diagnostic Explanations
    Saves the generated scenario into the database for unique, persistent ID tracking.
    """
    tmpl = random.choice(DYNAMIC_TEMPLATES)
    sender_name, sender_email = random.choice(tmpl["senders"])
    title = random.choice(tmpl["titles"])
    subject = random.choice(tmpl["subjects"])
    base_body = random.choice(tmpl["bodies"])
    
    title = clean_scenario_title(title)

    category_code = tmpl["category_code"]
    channel = tmpl["channel"]
    is_threat = tmpl["is_threat"]
    difficulty = tmpl["difficulty"]
    red_flags = tmpl["red_flags"]
    explanation = tmpl["explanation"]
    micro_lesson = tmpl["micro_lesson"]

    db = get_db()
    cur = db.execute("""
        INSERT INTO scenarios (category_code, channel, title, sender, sender_name, subject, body, is_threat, difficulty, red_flags, explanation, micro_lesson)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        category_code, channel, title, sender_email, sender_name, subject,
        base_body, 1 if is_threat else 0, difficulty,
        json.dumps(red_flags), explanation, micro_lesson
    ))
    db.commit()
    new_id = cur.lastrowid

    return {
        "id": new_id,
        "category_code": category_code,
        "channel": channel,
        "title": title,
        "sender": sender_email,
        "sender_name": sender_name,
        "subject": subject,
        "body": base_body,
        "is_threat": is_threat,
        "difficulty": difficulty,
        "red_flags": red_flags,
        "explanation": explanation,
        "micro_lesson": micro_lesson
    }

# ----------------- REAL-TIME AI THREAT & FILE INSPECTOR ENGINE ----------------- #

def extract_file_threat_data(file_storage):
    """
    Analyzes uploaded PDF or image screenshot:
    - Checks filename for risky extensions or double extensions (.pdf.exe, .png.scr, etc.)
    - Verifies file format and magic bytes
    - Extracts text content, embedded URLs, and suspicious active streams (/Launch, /JavaScript)
    Returns: (extracted_text, file_red_flags, file_meta)
    """
    filename = file_storage.filename or "uploaded_attachment"
    filename_lower = filename.lower()
    file_bytes = file_storage.read()
    file_meta = {
        "filename": filename,
        "size_kb": round(len(file_bytes) / 1024, 1)
    }
    file_red_flags = []
    extracted_text = ""

    # 1. Double extension and risky extension check
    if re.search(r'\.(pdf|png|jpg|jpeg|doc|docx|xls|xlsx)\.(exe|vbs|bat|cmd|scr|ps1|jar|iso)(\s|$)', filename_lower):
        file_red_flags.append(f"CRITICAL: Double extension malware payload masquerading as a document ({filename})")
    elif any(filename_lower.endswith(ext) for ext in ['.exe', '.vbs', '.bat', '.cmd', '.scr', '.ps1', '.iso']):
        file_red_flags.append(f"CRITICAL: Direct executable file uploaded ({filename}) — High Malware Threat")

    # 2. Check for PDF documents
    if filename_lower.endswith('.pdf') or file_bytes.startswith(b'%PDF'):
        file_meta["file_type"] = "PDF Document"
        if file_bytes.startswith(b'MZ'):
            file_red_flags.append("CRITICAL: Windows PE executable header (MZ) detected in PDF container!")

        raw_str = file_bytes.decode('latin1', errors='ignore')
        if '/JavaScript' in raw_str or '/JS' in raw_str:
            file_red_flags.append("Embedded Active JavaScript action detected inside PDF structure")
        if '/Launch' in raw_str:
            file_red_flags.append("Embedded /Launch exploit action detected (Attempts to run local binary)")
        if '/EmbeddedFiles' in raw_str:
            file_red_flags.append("Embedded hidden file attachment found inside PDF container")

        urls = re.findall(r'https?://[^\s<>"\'\(\)]+', raw_str)
        if urls:
            file_meta["embedded_urls"] = list(set(urls))
            extracted_text += " " + " ".join(urls)

        try:
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(file_bytes))
            file_meta["page_count"] = len(reader.pages)
            pdf_text = []
            for page in reader.pages:
                txt = page.extract_text()
                if txt:
                    pdf_text.append(txt)
            if pdf_text:
                extracted_text += "\n" + "\n".join(pdf_text)
        except Exception as e:
            file_red_flags.append(f"PDF structure warning or obfuscated stream: {str(e)[:50]}")

    # 3. Check for Image screenshots (PNG, JPG, JPEG)
    elif any(filename_lower.endswith(ext) for ext in ['.png', '.jpg', '.jpeg']) or file_bytes.startswith(b'\x89PNG') or file_bytes.startswith(b'\xff\xd8'):
        file_meta["file_type"] = "Screenshot / Image"
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(file_bytes))
            file_meta["dimensions"] = f"{img.width}x{img.height}"
            file_meta["format"] = img.format

            raw_str = file_bytes.decode('latin1', errors='ignore')
            urls = re.findall(r'https?://[^\s<>"\'\(\)]+', raw_str)
            if urls:
                file_red_flags.append(f"Suspicious URL string embedded directly inside image binary stream ({urls[0]})")
                extracted_text += " " + " ".join(urls)
        except Exception as e:
            file_red_flags.append(f"Image format anomaly or corruption: {str(e)[:50]}")

    else:
        file_meta["file_type"] = "Generic Attachment"
        raw_str = file_bytes.decode('latin1', errors='ignore')
        urls = re.findall(r'https?://[^\s<>"\'\(\)]+', raw_str)
        if urls:
            extracted_text += " " + " ".join(urls)

    return extracted_text, file_red_flags, file_meta

def inspect_text_or_url(input_text):
    """
    Heuristic and pattern engine evaluating user-submitted text, headers, and URLs.
    Checks for high-risk urgency/coercion terms, domain anomalies, shorteners, and payloads.
    Returns structured JSON: status, risk_score (0-100%), red_flags list, and recommendation.
    """
    text_lower = input_text.lower()
    red_flags = []
    risk_score = 8

    threat_patterns = [
        (r'\b(immediate(ly)? action (required|needed))\b', 'Extreme Urgency Sentiment (High-Pressure Psychological Trigger)'),
        (r'\b(account (is )?(suspended|locked|terminated|disabled))\b', 'Account Suspension / Disruption Coercion Threat'),
        (r'\b(verify (your )?(credentials|identity|password|pin|token))\b', 'Credential Harvesting & Secret Solicitation Indicator'),
        (r'\b(gift card|apple gift card|amazon gift card|itunes card)\b', 'Untraceable Payment Pretext (Gift Card Scam Hallmark)'),
        (r'\b(wire transfer|western union|crypto(currency)?|bitcoin)\b', 'Irreversible Electronic Funds Transfer Solicitation'),
        (r'\b(within (24|12|2|1) hours?|within 60 seconds|within 15 minutes)\b', 'Artificial Time Constraint / Countdown Pressure'),
        (r'\b(unauthorized access|suspicious login detected|security incident)\b', 'Fabricated Security Panic Alert'),
        (r'\b(disciplinary action|academic probation|legal summons|police warrant)\b', 'Fear & Disciplinary Coercion Pressure'),
        (r'\b(purge scheduled|permanently deleted|data loss)\b', 'Destructive Scare Tactic (Data Purge Pretext)'),
        (r'\b(update (your )?(direct deposit|banking|payroll))\b', 'Payroll / Banking Redirection Indicator'),
        (r'\b(selected for (a )?grant|claim (your )?(award|prize|token|bursary))\b', 'Financial Incentive & Greed Baiting')
    ]
    for pattern, label in threat_patterns:
        if re.search(pattern, text_lower):
            red_flags.append(label)
            risk_score += 18

    suspicious_tlds = ['.xyz', '.top', '.tk', '.cc', '.live', '.monster', '.buzz', '.info', '.biz', '.club', '.online', '.work']
    for tld in suspicious_tlds:
        if tld in text_lower:
            red_flags.append(f'Suspicious Top-Level Domain detected ({tld}) — commonly utilized in disposable phishing kits')
            risk_score += 24
            break

    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly', 'cutt.ly', 'shorturl.at']
    for s in shorteners:
        if s in text_lower:
            red_flags.append(f'Obfuscated URL Shortener detected ({s}) — masks true destination')
            risk_score += 20
            break

    lookalike_patterns = [
        (r'\b(fedx|dhl-express|ups-parcel)\b', 'Courier Delivery Brand Spoofing / Lookalike Domain'),
        (r'\b(paypa1|micros0ft|goo-gle|apple-auth)\b', 'Brand Impersonation & Character Substitution (Typosquatting)'),
        (r'\b(sso-login|auth-portal|campus-verify|verify-login)\b', 'Lookalike Single Sign-On (SSO) Portal Phishing Pattern')
    ]
    for pattern, label in lookalike_patterns:
        if re.search(pattern, text_lower):
            red_flags.append(label)
            risk_score += 22

    if re.search(r'\.(exe|pdf\.exe|vbs|bat|scr|cmd|ps1|iso|jar)(\s|$|\?|\/|"|\')', text_lower):
        red_flags.append('Executable or Double-Extension Payload detected (.exe, .pdf.exe) — High Malware Risk')
        risk_score += 35

    if 'http://' in text_lower and any(k in text_lower for k in ['login', 'verify', 'secure', 'portal', 'account', 'auth']):
        red_flags.append('Insecure Plain HTTP link soliciting authentication credentials')
        risk_score += 20

    if red_flags:
        risk_score = min(98, max(52, risk_score))
        status = "THREAT DETECTED"
        recommendation = "WARNING: Multiple high-risk social engineering or phishing markers were detected in this sample. Do NOT click any links, open attachments, or input passwords. Verify the communication out-of-band with the purported sender."
    else:
        risk_score = min(22, max(5, risk_score))
        status = "LIKELY SAFE / LEGITIMATE"
        recommendation = "No prominent phishing or social engineering red flags were detected in this text. However, always inspect the raw sender header and browser address bar before sharing sensitive credentials."

    return {
        "status": status,
        "risk_score": risk_score,
        "red_flags": red_flags,
        "recommendation": recommendation
    }

# ----------------- AUTHENTICATION (LANDING) ----------------- #

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')

        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template('login.html')

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE LOWER(username) = ?", (username,)).fetchone()

        if user:
            pwd_hash = user['password_hash'] if 'password_hash' in user.keys() else ''
            if pwd_hash and check_password_hash(pwd_hash, password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['full_name'] = user['full_name']
                session['role'] = user['role'] if ('role' in user.keys() and user['role']) else 'trainee'
                get_completed_drill_ids(user['id'])
                flash(f"Welcome back, {user['full_name']}!", "success")
                return redirect(url_for('dashboard'))


        flash("Invalid username or password. Please try again.", "danger")
        return render_template('login.html')

    return render_template('login.html')

@app.route('/demo-login', methods=['POST'])
def demo_login():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = 'demo'").fetchone()
    if not user:
        user = db.execute("SELECT * FROM users WHERE username = 'dhriti'").fetchone()
    if not user:
        cur = db.execute("INSERT INTO users (username, full_name, password_hash, role) VALUES (?, ?, ?, 'trainee')",
                         ('demo', 'Demo Trainee', generate_password_hash('password123')))
        db.commit()
        user_id = cur.lastrowid
        session['user_id'] = user_id
        session['username'] = 'demo'
        session['full_name'] = 'Demo Trainee'
        session['role'] = 'trainee'
    else:
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['full_name'] = user['full_name']
        session['role'] = user['role'] if ('role' in user.keys() and user['role']) else 'trainee'

    get_completed_drill_ids(session['user_id'])
    flash("Signed in as Demo User.", "success")
    return redirect(url_for('dashboard'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not full_name or not username or not password:
            flash("All fields are required.", "danger")
            return render_template('signup.html')

        if len(username) < 3:
            flash("Username must be at least 3 characters.", "danger")
            return render_template('signup.html')

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template('signup.html')

        if password != confirm_password:
            flash("Passwords do not match. Please re-enter.", "danger")
            return render_template('signup.html')

        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE LOWER(username) = ?", (username,)).fetchone()
        if existing:
            flash("This username is already taken. Please choose another or log in.", "danger")
            return render_template('signup.html')

        pwd_hash = generate_password_hash(password)
        cur = db.execute(
            "INSERT INTO users (username, full_name, password_hash) VALUES (?, ?, ?)",
            (username, full_name, pwd_hash)
        )
        new_user_id = cur.lastrowid

        db.execute("""
            INSERT INTO user_profiles (user_id, composite_risk_score, primary_weakness, category_stats, total_tests, accuracy_pct)
            VALUES (?, 50.0, 'Baseline (Not yet evaluated)', '{}', 0, 0.0)
        """, (new_user_id,))
        db.commit()

        session['user_id'] = new_user_id
        session['username'] = username
        session['full_name'] = full_name
        session['role'] = 'trainee'
        session['completed_drills'] = []

        flash(f"Account successfully created! Welcome, {full_name}!", "success")
        return redirect(url_for('dashboard'))

    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been signed out successfully.", "success")
    return redirect(url_for('login'))

# ----------------- MAIN DASHBOARD ----------------- #

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    profile = fetch_user_profile_data(user_id)
    attempts = fetch_user_attempts(user_id)
    all_scenarios = fetch_all_scenarios()
    completed_ids = get_completed_drill_ids(user_id)
    completed_count = len(completed_ids)
    next_drill_number = completed_count + 1

    uncompleted_baseline = [sid for sid in BASELINE_SCENARIO_IDS if sid not in completed_ids]
    if uncompleted_baseline:
        next_scenario_id = uncompleted_baseline[0]
        next_rationale = f"Adaptive Awareness Drill {next_drill_number}"
    else:
        next_scenario_id = None
        next_rationale = f"Dynamic Procedural Drill {next_drill_number}"

    return render_template(
        'dashboard.html',
        profile=profile,
        attempts=attempts,
        all_scenarios=all_scenarios,
        next_scenario_id=next_scenario_id,
        next_rationale=next_rationale,
        completed_count=completed_count,
        next_drill_number=next_drill_number
    )

# ----------------- GLOBAL LEADERBOARD (CTF / HACKERRANK STYLE) ----------------- #

@app.route('/leaderboard')
def leaderboard():
    db = get_db()
    rows = db.execute("""
        SELECT 
            u.id as user_id,
            u.username,
            u.full_name,
            COUNT(a.id) as drills_completed,
            COALESCE(SUM(CASE WHEN a.is_correct = 1 THEN 1 ELSE 0 END), 0) as correct_count,
            COALESCE(AVG(a.response_time_sec), 0.0) as avg_speed,
            COALESCE(p.composite_risk_score, 50.0) as risk_score
        FROM users u
        LEFT JOIN user_attempts a ON u.id = a.user_id
        LEFT JOIN user_profiles p ON u.id = p.user_id
        GROUP BY u.id, u.username, u.full_name
    """).fetchall()

    leaderboard_data = []
    for r in rows:
        total = r['drills_completed']
        correct = r['correct_count']
        accuracy_pct = round((correct / total * 100), 1) if total > 0 else 0.0
        avg_speed = round(r['avg_speed'], 1)

        base_points = correct * 100
        participation_points = total * 20
        accuracy_bonus = int(accuracy_pct * 2)
        speed_bonus = int(max(0, (15.0 - min(avg_speed, 15.0)) * 5)) if total > 0 else 0
        composite_score = base_points + participation_points + accuracy_bonus + speed_bonus

        if total >= 10 and accuracy_pct >= 60.0:
            badge = "Master Defender 🛡️"
            badge_class = "badge-safe"
        elif total >= 5:
            badge = "Cyber Specialist ⚔️"
            badge_class = "badge-ai"
        elif total > 0:
            badge = "Security Cadet 🔰"
            badge_class = "badge"
        else:
            badge = "Unrated Trainee ⏳"
            badge_class = "badge"

        leaderboard_data.append({
            "user_id": r['user_id'],
            "username": r['username'],
            "full_name": r['full_name'],
            "drills_completed": total,
            "correct_count": correct,
            "accuracy_pct": accuracy_pct,
            "avg_speed": avg_speed,
            "score": composite_score,
            "badge": badge,
            "badge_class": badge_class,
            "risk_score": round(r['risk_score'], 1)
        })

    leaderboard_data.sort(key=lambda x: (x['score'], x['accuracy_pct'], x['drills_completed']), reverse=True)

    for idx, user in enumerate(leaderboard_data, 1):
        user['rank'] = idx

    current_user_id = session.get('user_id')

    return render_template(
        'leaderboard.html',
        leaderboard=leaderboard_data,
        current_user_id=current_user_id
    )

# ----------------- SIMULATION DRILL ENGINE ----------------- #

@app.route('/simulation')
@app.route('/next_drill')
@app.route('/drill')
@app.route('/drill/<int:scenario_id>')
@login_required
def drill(scenario_id=None):
    user_id = session['user_id']
    completed_ids = get_completed_drill_ids(user_id)
    completed_count = len(completed_ids)

    if scenario_id is not None:
        scenario = get_scenario_by_id(scenario_id)
        if scenario:
            if scenario['id'] in BASELINE_SCENARIO_IDS:
                drill_number = BASELINE_SCENARIO_IDS.index(scenario['id']) + 1
            else:
                drill_number = completed_count + 1
            rationale = f"Targeted Catalog Drill: Scenario {drill_number} ({scenario['category_code']} vector)."
            return render_template(
                'drill.html',
                scenario=scenario,
                drill_number=drill_number,
                completed_count=completed_count,
                adaptive_rationale=rationale
            )

    drill_number = completed_count + 1
    uncompleted_baseline = [sid for sid in BASELINE_SCENARIO_IDS if sid not in completed_ids]
    if uncompleted_baseline:
        next_id = uncompleted_baseline[0]
        scenario = get_scenario_by_id(next_id)
        if scenario:
            rationale = f"Diagnostic Evaluation Drill {drill_number}: Evaluating baseline vigilance across {scenario['category_code']} vectors."
            return render_template(
                'drill.html',
                scenario=scenario,
                drill_number=drill_number,
                completed_count=completed_count,
                adaptive_rationale=rationale
            )

    scenario = generate_dynamic_scenario()
    rationale = f"Adaptive Procedural Drill {drill_number}: AI-synthesized simulation targeting {scenario['category_code']} vectors."
    return render_template(
        'drill.html',
        scenario=scenario,
        drill_number=drill_number,
        completed_count=completed_count,
        adaptive_rationale=rationale
    )

@app.route('/drill/submit', methods=['POST'])
@login_required
def drill_submit():
    user_id = session['user_id']
    scenario_id = int(request.form.get('scenario_id', 1))
    drill_number = int(request.form.get('drill_number', len(get_completed_drill_ids(user_id)) + 1))
    choice_str = request.form.get('user_choice', 'safe')
    user_choice = True if choice_str == 'threat' else False

    try:
        response_time = float(request.form.get('response_time', 5.0))
    except ValueError:
        response_time = 5.0

    scenario = get_scenario_by_id(scenario_id)
    if not scenario:
        flash("Scenario not found.", "danger")
        return redirect(url_for('dashboard'))

    is_correct = (user_choice == scenario["is_threat"])

    db = get_db()
    cur = db.execute("""
        INSERT INTO user_attempts (user_id, scenario_id, user_choice, is_correct, response_time_sec)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, scenario_id, 1 if user_choice else 0, 1 if is_correct else 0, response_time))
    attempt_id = cur.lastrowid
    db.commit()

    completed = session.get('completed_drills', [])
    if scenario_id not in completed:
        completed.append(scenario_id)
        session['completed_drills'] = completed

    all_attempts = fetch_user_attempts(user_id)
    new_profile = calculate_user_risk_profile(all_attempts)

    db.execute("""
        UPDATE user_profiles
        SET composite_risk_score = ?,
            primary_weakness = ?,
            category_stats = ?,
            total_tests = ?,
            accuracy_pct = ?,
            last_updated = CURRENT_TIMESTAMP
        WHERE user_id = ?
    """, (
        new_profile["composite_risk_score"],
        new_profile["primary_weakness"],
        json.dumps(new_profile["category_stats"]),
        new_profile["total_tests"],
        new_profile["accuracy_pct"],
        user_id
    ))
    db.commit()

    return redirect(url_for('explanation', attempt_id=attempt_id, drill_number=drill_number))

# ----------------- AI DIAGNOSTIC EXPLANATION ----------------- #

@app.route('/explanation/<int:attempt_id>')
@login_required
def explanation(attempt_id):
    user_id = session['user_id']
    db = get_db()
    attempt = db.execute("""
        SELECT a.*, s.title, s.category_code, s.channel, s.sender, s.sender_name, s.subject,
               s.body, s.is_threat, s.difficulty, s.red_flags, s.explanation, s.micro_lesson
        FROM user_attempts a
        JOIN scenarios s ON a.scenario_id = s.id
        WHERE a.id = ? AND a.user_id = ?
    """, (attempt_id, user_id)).fetchone()

    if not attempt:
        flash("Explanation record not found.", "danger")
        return redirect(url_for('dashboard'))

    attempt_order = db.execute("""
        SELECT COUNT(*) FROM user_attempts 
        WHERE user_id = ? AND id <= ?
    """, (user_id, attempt_id)).fetchone()[0]
    drill_number = request.args.get('drill_number', type=int) or attempt_order or 1

    scenario_title = clean_scenario_title(attempt["title"])
    scenario = {
        "id": attempt["scenario_id"],
        "category_code": attempt["category_code"],
        "channel": attempt["channel"],
        "title": scenario_title,
        "clean_title": scenario_title,
        "sender": attempt["sender"],
        "sender_name": attempt["sender_name"],
        "subject": attempt["subject"],
        "body": attempt["body"],
        "is_threat": bool(attempt["is_threat"]),
        "difficulty": attempt["difficulty"],
        "red_flags": json.loads(attempt["red_flags"]) if attempt["red_flags"] else [],
        "explanation": attempt["explanation"],
        "micro_lesson": attempt["micro_lesson"]
    }

    user_choice = bool(attempt["user_choice"])
    is_correct = bool(attempt["is_correct"])
    response_time = attempt["response_time_sec"]

    feedback = generate_explainable_feedback(scenario, user_choice, is_correct, response_time)

    completed_ids = get_completed_drill_ids(user_id)
    completed_count = len(completed_ids)
    upcoming_drill_number = completed_count + 1

    uncompleted_baseline = [sid for sid in BASELINE_SCENARIO_IDS if sid not in completed_ids]
    if uncompleted_baseline:
        next_scenario_id = uncompleted_baseline[0]
        next_rationale = f"Adaptive Awareness Drill {upcoming_drill_number}"
    else:
        next_scenario_id = None
        next_rationale = f"Dynamic Procedural Drill {upcoming_drill_number}"

    return render_template(
        'explanation.html',
        attempt=attempt,
        scenario=scenario,
        drill_number=drill_number,
        upcoming_drill_number=upcoming_drill_number,
        feedback=feedback,
        user_choice=user_choice,
        is_correct=is_correct,
        response_time=response_time,
        next_scenario_id=next_scenario_id,
        next_rationale=next_rationale
    )

# ----------------- REAL-TIME AI INSPECTOR API ENDPOINT (TEXT & ATTACHMENT SCANNING) ----------------- #

@app.route('/api/inspect', methods=['POST'])
@login_required
def api_inspect():
    input_text = ""
    file_red_flags = []
    file_meta = None

    if request.is_json:
        data = request.get_json(silent=True) or {}
        input_text = (data.get('input_text') or '').strip()
    else:
        input_text = (request.form.get('input_text') or '').strip()

    uploaded_file = request.files.get('file')
    if uploaded_file and uploaded_file.filename:
        extracted_text, f_flags, f_meta = extract_file_threat_data(uploaded_file)
        file_red_flags.extend(f_flags)
        file_meta = f_meta
        if extracted_text:
            input_text = (input_text + "\n" + extracted_text).strip()

    if not input_text and not file_red_flags:
        return jsonify({
            "status": "INPUT REQUIRED",
            "risk_score": 0,
            "red_flags": ["No text, link, or supported attachment provided for inspection."],
            "recommendation": "Please paste email/message content or upload a suspicious PDF/image screenshot to inspect."
        }), 400

    result = inspect_text_or_url(input_text)

    if file_red_flags:
        result["red_flags"] = list(dict.fromkeys(file_red_flags + result["red_flags"]))
        result["risk_score"] = min(99, max(result["risk_score"], 85))
        result["status"] = "THREAT DETECTED"
        result["recommendation"] = "CRITICAL FILE ANOMALY: The uploaded attachment contains dangerous markers (e.g., executable double extensions, active launch triggers, or embedded links). Do not open or execute this file."

    if file_meta:
        result["file_info"] = file_meta

    return jsonify(result)

# ----------------- JSON API ENDPOINTS ----------------- #

@app.route('/api/submit', methods=['POST'])
@login_required
def api_submit():
    data = request.get_json(silent=True) or request.form
    user_id = session['user_id']
    scenario_id = int(data.get('scenario_id'))
    choice_str = data.get('user_choice', 'safe')
    user_choice = True if choice_str == 'threat' else False

    try:
        response_time = float(data.get('response_time', 5.0))
    except ValueError:
        response_time = 5.0

    scenario = get_scenario_by_id(scenario_id)
    if not scenario:
        return jsonify({"error": "Scenario not found"}), 404

    is_correct = (user_choice == scenario["is_threat"])

    db = get_db()
    cur = db.execute("""
        INSERT INTO user_attempts (user_id, scenario_id, user_choice, is_correct, response_time_sec)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, scenario_id, 1 if user_choice else 0, 1 if is_correct else 0, response_time))
    attempt_id = cur.lastrowid
    db.commit()

    completed = session.get('completed_drills', [])
    if scenario_id not in completed:
        completed.append(scenario_id)
        session['completed_drills'] = completed

    all_attempts = fetch_user_attempts(user_id)
    new_profile = calculate_user_risk_profile(all_attempts)

    db.execute("""
        UPDATE user_profiles
        SET composite_risk_score = ?,
            primary_weakness = ?,
            category_stats = ?,
            total_tests = ?,
            accuracy_pct = ?,
            last_updated = CURRENT_TIMESTAMP
        WHERE user_id = ?
    """, (
        new_profile["composite_risk_score"],
        new_profile["primary_weakness"],
        json.dumps(new_profile["category_stats"]),
        new_profile["total_tests"],
        new_profile["accuracy_pct"],
        user_id
    ))
    db.commit()

    feedback = generate_explainable_feedback(scenario, user_choice, is_correct, response_time)

    completed_ids = get_completed_drill_ids(user_id)
    uncompleted_baseline = [sid for sid in BASELINE_SCENARIO_IDS if sid not in completed_ids]
    if uncompleted_baseline:
        next_scenario = get_scenario_by_id(uncompleted_baseline[0])
        next_rationale = f"Baseline Scenario #{next_scenario['id']}"
    else:
        next_scenario = generate_dynamic_scenario()
        next_rationale = f"Dynamic Procedural Engine #{next_scenario['id']}"

    return jsonify({
        "success": True,
        "attempt_id": attempt_id,
        "feedback": feedback,
        "profile": new_profile,
        "next_scenario": next_scenario,
        "next_rationale": next_rationale,
        "attempts": all_attempts,
        "redirect_url": url_for('explanation', attempt_id=attempt_id)
    })

@app.route('/api/reset', methods=['POST'])
@login_required
def api_reset():
    user_id = session['user_id']
    session['completed_drills'] = []
    db = get_db()
    db.execute("DELETE FROM user_attempts WHERE user_id = ?", (user_id,))
    db.execute("""
        UPDATE user_profiles
        SET composite_risk_score = 50.0,
            primary_weakness = 'Baseline (Not yet evaluated)',
            category_stats = '{}',
            total_tests = 0,
            accuracy_pct = 0.0,
            last_updated = CURRENT_TIMESTAMP
        WHERE user_id = ?
    """, (user_id,))
    db.commit()

    first_scenario = get_scenario_by_id(1)
    new_profile = {
        "composite_risk_score": 50.0,
        "primary_weakness": "Baseline (Not yet evaluated)",
        "category_stats": {},
        "total_tests": 0,
        "accuracy_pct": 0.0,
        "risk_level": "Unrated (Baseline)"
    }
    return jsonify({
        "success": True,
        "profile": new_profile,
        "next_scenario": first_scenario,
        "next_rationale": "Initial Diagnostic: Establishing your baseline cybersecurity vigilance profile."
    })

# =========================================================================
# ENHANCEMENT MODULES: 8 EXPANDED CYBERSECURITY CAPABILITIES
# =========================================================================

# ----------------- 1. PERSONAL ANALYTICS DASHBOARD ----------------- #
@app.route('/analytics')
@login_required
def analytics_dashboard():
    db = get_db()
    data = get_personal_analytics(db, session['user_id'])
    if not data:
        flash("Could not retrieve personal analytics.", "danger")
        return redirect(url_for('dashboard'))
    return render_template('analytics.html', data=data)

# Alias for drill_scenario to ensure smooth navigation
@app.route('/drill/<int:scenario_id>', endpoint='drill_scenario')
@login_required
def drill_scenario_alias(scenario_id):
    return drill(scenario_id=scenario_id)

# ----------------- 2. REALISTIC PHISHING SIMULATION ----------------- #
@app.route('/phishing')
@login_required
def phishing_index():
    difficulty = request.args.get('difficulty')
    db = get_db()
    scenarios = get_all_phishing_scenarios(db, user_id=session.get('user_id'), difficulty=difficulty)
    user_completed_count = sum(1 for s in scenarios if s['user_status'] == 'Passed ✓')
    return render_template('phishing.html', scenarios=scenarios, current_diff=difficulty, user_completed_count=user_completed_count)

@app.route('/phishing/<int:scenario_id>')
@login_required
def phishing_drill(scenario_id):
    db = get_db()
    scenario = get_phishing_scenario_by_id(db, scenario_id)
    if not scenario:
        flash("Phishing scenario not found.", "warning")
        return redirect(url_for('phishing_index'))
    return render_template('phishing_drill.html', scenario=scenario)

@app.route('/phishing/<int:scenario_id>/portal')
@login_required
def phishing_portal(scenario_id):
    db = get_db()
    scenario = get_phishing_scenario_by_id(db, scenario_id)
    if not scenario:
        return "Portal not found", 404
    return render_template('phishing_portal.html', scenario=scenario)

@app.route('/phishing/submit', methods=['POST'])
@login_required
def phishing_submit():
    data = request.get_json(silent=True) or request.form
    scenario_id = int(data.get('scenario_id', 0))
    verdict = data.get('verdict', 'phishing')
    indicators = data.get('indicators', [])
    response_time = int(data.get('response_time', 10))

    db = get_db()
    result = evaluate_phishing_attempt(db, session['user_id'], scenario_id, verdict, indicators, response_time)
    if not result:
        return jsonify({"success": False, "error": "Invalid scenario"}), 400
    return jsonify({"success": True, "result": result})

# ----------------- 3. CTF MISSION MODE ----------------- #
@app.route('/ctf')
@login_required
def ctf_index():
    category = request.args.get('category')
    db = get_db()
    challenges = get_all_ctf_challenges(db, user_id=session.get('user_id'), category=category)
    solved_count = sum(1 for c in challenges if c['is_solved'])
    user_ctf_score = db.execute("SELECT COALESCE(SUM(points_awarded), 0) FROM user_ctf_completions WHERE user_id = ?", (session['user_id'],)).fetchone()[0]
    return render_template('ctf.html', challenges=challenges, current_cat=category, solved_count=solved_count, user_ctf_score=user_ctf_score)

@app.route('/ctf/<int:challenge_id>')
@login_required
def ctf_challenge_view(challenge_id):
    db = get_db()
    challenge = get_ctf_challenge_by_id(db, challenge_id, user_id=session.get('user_id'))
    if not challenge:
        flash("CTF challenge not found.", "warning")
        return redirect(url_for('ctf_index'))
    return render_template('ctf_challenge.html', challenge=challenge)

@app.route('/ctf/submit', methods=['POST'])
@login_required
def ctf_submit_flag():
    data = request.get_json(silent=True) or request.form
    challenge_id = int(data.get('challenge_id', 0))
    flag = data.get('flag', '').strip()
    hints_used = int(data.get('hints_used', 0))

    db = get_db()
    success, message, pts = validate_ctf_flag(db, session['user_id'], challenge_id, flag, hints_used)
    return jsonify({"success": success, "message": message, "points": pts})

# ----------------- 4. AI THREAT ANALYST ----------------- #
@app.route('/ai-analyst')
@login_required
def ai_analyst_view():
    db = get_db()
    scenario_id = request.args.get('scenario_id', type=int)
    scenarios = db.execute("SELECT id, title, category_code, body as content, explanation FROM scenarios ORDER BY id ASC").fetchall()
    
    selected_scenario = None
    if scenario_id:
        selected_scenario = db.execute("SELECT * FROM scenarios WHERE id = ?", (scenario_id,)).fetchone()
    if not selected_scenario and scenarios:
        selected_scenario = scenarios[0]

    report = generate_structured_threat_report(selected_scenario)
    return render_template('ai_analyst.html', scenarios=scenarios, selected_id=scenario_id or (selected_scenario['id'] if selected_scenario else None), report=report)

@app.route('/ai-analyst/generate', methods=['POST'])
@login_required
def ai_analyst_generate():
    data = request.get_json(silent=True) or {}
    scenario_id = data.get('scenario_id')
    custom_text = data.get('custom_text', '').strip()

    db = get_db()
    if scenario_id:
        scen = db.execute("SELECT * FROM scenarios WHERE id = ?", (scenario_id,)).fetchone()
        if scen:
            report = generate_structured_threat_report(scen)
            return jsonify({"success": True, "report": report})

    if custom_text:
        synthetic = {
            "title": "Custom Inspected Message",
            "body": custom_text,
            "category_code": "URGENCY",
            "is_threat": 1,
            "red_flags": "Unverified sender domain, embedded external links, generic greeting",
            "explanation": "Simulated forensic scan of custom submitted communication."
        }
        report = generate_structured_threat_report(synthetic)
        return jsonify({"success": True, "report": report})

    return jsonify({"success": False, "error": "No scenario or text provided"}), 400

# ----------------- 5. INCIDENT RESPONSE WAR ROOM ----------------- #
@app.route('/war-room')
@login_required
def war_room_index():
    db = get_db()
    scenarios = get_all_war_room_scenarios(db, user_id=session.get('user_id'))
    return render_template('war_room.html', scenarios=scenarios)

@app.route('/war-room/<int:scenario_id>')
@login_required
def war_room_launch(scenario_id):
    db = get_db()
    session_id = start_or_get_war_room_session(db, session['user_id'], scenario_id)
    if not session_id:
        flash("War room scenario not found.", "warning")
        return redirect(url_for('war_room_index'))
    state = get_war_room_session_state(db, session_id, session['user_id'])
    if state["is_finished"]:
        return redirect(url_for('war_room_debrief', session_id=session_id))
    return render_template('war_room_mission.html', state=state)

@app.route('/war-room/action', methods=['POST'])
@login_required
def war_room_action():
    data = request.get_json(silent=True) or request.form
    session_id = data.get('session_id')
    option_id = data.get('option_id')
    db = get_db()
    success, message, res_data = record_war_room_decision(db, session_id, session['user_id'], option_id)
    return jsonify({"success": success, "message": message, "data": res_data})

@app.route('/war-room/debrief/<session_id>')
@login_required
def war_room_debrief(session_id):
    db = get_db()
    state = get_war_room_session_state(db, session_id, session['user_id'])
    if not state:
        flash("Incident session not found.", "warning")
        return redirect(url_for('war_room_index'))
    return render_template('war_room_debrief.html', state=state)

# ----------------- 6. SKILLS, BADGES & CERTIFICATES ----------------- #
@app.route('/skills')
@login_required
def skills_matrix():
    db = get_db()
    skills = calculate_user_skills(db, session['user_id'])
    badges = get_all_badges_with_user_status(db, session['user_id'])
    earned_count = sum(1 for b in badges if b['is_unlocked'])
    return render_template('skills.html', skills=skills, all_badges=badges, earned_badge_count=earned_count)

@app.route('/certificate')
@login_required
def certificate():
    db = get_db()
    cert, err = issue_or_get_certificate(db, session['user_id'])
    return render_template('certificate.html', certificate=cert, error=err)

@app.route('/verify-certificate/<cert_id>')
def verify_certificate(cert_id):
    db = get_db()
    cert = verify_certificate_by_id(db, cert_id)
    return render_template('verify_certificate.html', certificate=cert, cert_id=cert_id)

# ----------------- 7. THREAT INTELLIGENCE CENTER ----------------- #
@app.route('/threat-intel')
def threat_intel_feed():
    q = request.args.get('q', '').strip()
    severity = request.args.get('severity', '').strip()
    db = get_db()
    records = get_threat_intel_records(db, search_query=q or None, severity=severity or None)
    return render_template('threat_intel.html', records=records, search_query=q, severity=severity)

@app.route('/threat-intel/sync', methods=['POST'])
def threat_intel_sync():
    db = get_db()
    success, msg = sync_threat_intel_feed(db)
    flash(msg, "info" if success else "warning")
    return redirect(url_for('threat_intel_feed'))

# ----------------- 8. ADMIN & TRAINER PANEL ----------------- #
@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    metrics = get_admin_metrics(db)
    drills = get_all_scenarios_admin(db)
    users = get_all_users_admin(db)
    return render_template('admin.html', metrics=metrics, drills=drills, users=users)

@app.route('/admin/drill/new', methods=['GET', 'POST'])
@admin_required
def admin_new_drill():
    db = get_db()
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        cat = request.form.get('category_code', 'URGENCY')
        channel = request.form.get('channel', 'email')
        difficulty = request.form.get('difficulty', 'beginner')
        is_threat = 1 if request.form.get('is_threat') == '1' else 0
        content = request.form.get('content', '').strip()
        red_flags = request.form.get('red_flags', '').strip()
        explanation = request.form.get('explanation', '').strip()

        db.execute("""
            INSERT INTO scenarios (title, category_code, channel, difficulty, is_threat, body, red_flags, explanation, status, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'published', 'admin')
        """, (title, cat, channel, difficulty, is_threat, content, red_flags, explanation))
        db.commit()
        flash(f"Drill '{title}' successfully created and published.", "success")
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_drill_form.html', drill=None)

@app.route('/admin/drill/edit/<int:scenario_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_drill(scenario_id):
    db = get_db()
    drill = db.execute("SELECT * FROM scenarios WHERE id = ?", (scenario_id,)).fetchone()
    if not drill:
        flash("Drill not found.", "warning")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        cat = request.form.get('category_code', 'URGENCY')
        channel = request.form.get('channel', 'email')
        difficulty = request.form.get('difficulty', 'beginner')
        is_threat = 1 if request.form.get('is_threat') == '1' else 0
        content = request.form.get('content', '').strip()
        red_flags = request.form.get('red_flags', '').strip()
        explanation = request.form.get('explanation', '').strip()

        db.execute("""
            UPDATE scenarios 
            SET title = ?, category_code = ?, channel = ?, difficulty = ?, is_threat = ?, body = ?, red_flags = ?, explanation = ?
            WHERE id = ?
        """, (title, cat, channel, difficulty, is_threat, content, red_flags, explanation, scenario_id))
        db.commit()
        flash(f"Drill #{scenario_id} updated successfully.", "success")
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_drill_form.html', drill=drill)

@app.route('/admin/drill/toggle/<int:scenario_id>', methods=['POST'])
@admin_required
def admin_toggle_drill(scenario_id):
    db = get_db()
    success, msg = toggle_scenario_status(db, scenario_id)
    flash(msg, "info" if success else "danger")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/toggle/<int:user_id>', methods=['POST'])
@admin_required
def admin_toggle_user_role(user_id):
    db = get_db()
    success, msg = toggle_user_role(db, user_id, session.get('user_id'))
    flash(msg, "info" if success else "danger")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/export/<report_type>')
@admin_required
def admin_export(report_type):
    from flask import Response
    db = get_db()
    csv_data = export_training_report_csv(db, report_type)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=threat_vector_{report_type}_report.csv"}
    )

if __name__ == '__main__':
    ensure_tables()
    port = int(os.environ.get('PORT', 5000))
    print(f"Threat Vector AI Server running on port {port}")
    app.run(host='0.0.0.0', port=port, debug=True)
