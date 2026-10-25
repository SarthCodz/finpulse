# FinPulse - FNB Challenge entry (HackPSU Fall 2026)
# Run with:  streamlit run app.py

import hashlib          # stdlib: used for salted password hashing and report IDs
import hmac             # stdlib: constant-time comparison so hash checks don't leak timing info
import html             # stdlib: html.escape() stops user text from injecting HTML into the report
import io               # stdlib: lets pandas read an uploaded CSV from memory
import json             # stdlib: expenses are stored in SQLite as a JSON string
import os               # stdlib: random bytes for password salts
import sqlite3          # stdlib: embedded database (finpulse.db)
import uuid             # stdlib: stable unique IDs for each expense row
from datetime import datetime  # used to timestamp each report

import pandas as pd                      # tables + charts
import streamlit as st                   # the web UI
import streamlit.components.v1 as components  # renders the printable HTML report

# Page configuration must be the first Streamlit call.
st.set_page_config(page_title="FinPulse | FNB Challenge", page_icon="💡", layout="wide")

# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------
DB_FILE = "finpulse.db"  # database file created next to app.py on first run


def safe_float(val, default=0.0):
    """Turn '$1,200.50' style text into a float; never raises."""
    try:
        clean_val = str(val).replace("$", "").replace(",", "").strip()  # strip currency formatting
        return float(clean_val) if clean_val else default               # empty string -> default
    except ValueError:
        return default                                                  # unparseable -> default


def hash_pw(password, salt=None):
    """PBKDF2-HMAC-SHA256 with a random per-user salt. Returns 'salt_hex$hash_hex'."""
    salt = salt or os.urandom(16)  # new random 16-byte salt unless verifying an existing one
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)  # 200k iterations slows brute force
    return f"{salt.hex()}${digest.hex()}"


def verify_pw(password, stored):
    """Check a password attempt against a stored 'salt$hash' string."""
    if not stored or "$" not in stored:           # malformed or legacy plaintext value
        return False
    salt_hex, _ = stored.split("$", 1)            # recover the salt that was used originally
    candidate = hash_pw(password, bytes.fromhex(salt_hex))  # hash the attempt with the same salt
    return hmac.compare_digest(candidate, stored)  # constant-time equality


def make_report_id(username):
    """Unique reference per generated report: hash of username + timestamp, shortened."""
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")                       # when the report was generated
    digest = hashlib.sha256(f"{username}|{stamp}".encode()).hexdigest()   # fingerprint of who + when
    return f"FP-{stamp[:8]}-{digest[:8].upper()}"                         # e.g. FP-20261024-9A3C01BE


# ---------------------------------------------------------
# DATABASE PERSISTENCE LAYER (SQLite)
# ---------------------------------------------------------
def init_db():
    """Create the users table and seed the demo account 'alex' if missing."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            full_name TEXT,
            occupation TEXT,
            monthly_income REAL,
            current_savings REAL,
            custom_expenses TEXT
        )
    """)
    c.execute("SELECT 1 FROM users WHERE username = 'alex'")  # is the demo user already there?
    if not c.fetchone():
        default_expenses = [
            {"id": str(uuid.uuid4()), "name": "Rent & Housing", "amount": "1500.00", "category": "Fixed"},
            {"id": str(uuid.uuid4()), "name": "Subscriptions & Streaming", "amount": "80.00", "category": "Discretionary"},
            {"id": str(uuid.uuid4()), "name": "Groceries & Food", "amount": "400.00", "category": "Discretionary"},
            {"id": str(uuid.uuid4()), "name": "Taxes & Withholdings", "amount": "420.00", "category": "Fixed"},
            {"id": str(uuid.uuid4()), "name": "Travel & Trips", "amount": "200.00", "category": "Discretionary"},
            {"id": str(uuid.uuid4()), "name": "Miscellaneous", "amount": "100.00", "category": "Discretionary"},
        ]
        c.execute(
            "INSERT INTO users VALUES ('alex', ?, 'Alex Morgan', 'Software Engineer', 5500.0, 8000.0, ?)",
            (hash_pw("password123"), json.dumps(default_expenses)),  # demo password is stored HASHED, not plaintext
        )
    conn.commit()
    conn.close()


def get_password_hash(username):
    """Fetch the stored password hash for a username (None if no such user)."""
    conn = sqlite3.connect(DB_FILE)
    row = conn.execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row[0] if row else None


def load_user_data(username):
    """Load a user's profile + expenses as a dict (None if no such user)."""
    conn = sqlite3.connect(DB_FILE)
    row = conn.execute(
        "SELECT username, full_name, occupation, monthly_income, current_savings, custom_expenses "
        "FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()
    if row:
        return {
            "username": row[0],
            "full_name": row[1],
            "occupation": row[2],
            "monthly_income": str(row[3]),
            "current_savings": str(row[4]),
            "custom_expenses": json.loads(row[5]),  # JSON text -> list of dicts
        }
    return None


def create_new_user(username, password, full_name, occupation):
    """Insert a new user with a hashed password. Returns False if the username is taken."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    if c.fetchone():
        conn.close()
        return False
    starter_expenses = [
        {"id": str(uuid.uuid4()), "name": "Groceries & Food", "amount": "400.00", "category": "Discretionary"},
        {"id": str(uuid.uuid4()), "name": "Rent & Housing", "amount": "1200.00", "category": "Fixed"},
    ]
    c.execute(
        "INSERT INTO users VALUES (?, ?, ?, ?, 4000.0, 5000.0, ?)",
        (username, hash_pw(password), full_name, occupation, json.dumps(starter_expenses)),
    )
    conn.commit()
    conn.close()
    return True


def save_user_data():
    """Write the current session's profile + expenses back to SQLite."""
    if not st.session_state.get("logged_in") or not st.session_state.get("username"):
        return  # nothing to save when nobody is signed in
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "UPDATE users SET full_name = ?, occupation = ?, monthly_income = ?, "
        "current_savings = ?, custom_expenses = ? WHERE username = ?",
        (
            st.session_state.user_name,
            st.session_state.user_job,
            safe_float(st.session_state.monthly_income),
            safe_float(st.session_state.current_savings),
            json.dumps(st.session_state.custom_expenses),
            st.session_state.username,
        ),
    )
    conn.commit()
    conn.close()


def start_session(user_data):
    """Copy a loaded user's data into st.session_state and mark them logged in."""
    st.session_state.logged_in = True
    st.session_state.username = user_data["username"]
    st.session_state.user_name = user_data["full_name"]
    st.session_state.user_job = user_data["occupation"]
    st.session_state.monthly_income = user_data["monthly_income"]
    st.session_state.current_savings = user_data["current_savings"]
    st.session_state.custom_expenses = user_data["custom_expenses"]


# ---------------------------------------------------------
# CSV STATEMENT IMPORT (rule-based categoriser)
# ---------------------------------------------------------
# Keyword -> (clean label, Fixed/Discretionary). First match wins.
CATEGORY_RULES = [
    (("rent", "landlord", "apartment", "mortgage"), ("Rent & Housing", "Fixed")),
    (("electric", "water bill", "utility", "internet", "comcast", "verizon", "t-mobile", "gas bill"), ("Utilities & Phone", "Fixed")),
    (("insurance", "geico", "state farm"), ("Insurance", "Fixed")),
    (("loan", "student loan", "navient", "car payment"), ("Loan Payments", "Fixed")),
    (("netflix", "spotify", "hulu", "disney", "youtube", "subscription", "prime"), ("Subscriptions & Streaming", "Discretionary")),
    (("grocer", "giant", "wegmans", "trader joe", "walmart", "aldi", "whole foods"), ("Groceries & Food", "Discretionary")),
    (("restaurant", "doordash", "ubereats", "grubhub", "starbucks", "mcdonald", "chipotle", "panera", "domino"), ("Dining Out", "Discretionary")),
    (("uber", "lyft", "airline", "delta", "hotel", "airbnb", "amtrak"), ("Travel & Trips", "Discretionary")),
]


def categorize(description):
    """Return (label, category) for a transaction description using keyword rules."""
    text = str(description).lower()               # case-insensitive matching
    for keywords, result in CATEGORY_RULES:       # walk the rules in order
        if any(k in text for k in keywords):      # any keyword present in the description?
            return result
    return ("Miscellaneous", "Discretionary")     # fallback bucket


def parse_statement(file_bytes):
    """Read a bank CSV (needs description + amount columns) -> list of monthly-total expense dicts."""
    df = pd.read_csv(io.BytesIO(file_bytes))                       # parse the uploaded bytes
    df.columns = [str(c).strip().lower() for c in df.columns]      # normalise header names
    desc_col = next((c for c in df.columns if c in ("description", "merchant", "name", "memo", "details")), None)
    amt_col = next((c for c in df.columns if c in ("amount", "debit", "withdrawal", "cost")), None)
    if desc_col is None or amt_col is None:
        raise ValueError("CSV needs a description column (description/merchant/name) and an amount column (amount/debit).")
    totals = {}                                                    # (label, category) -> summed spend
    for _, r in df.iterrows():
        amt = safe_float(r[amt_col])
        if amt == 0:
            continue                                               # skip blanks
        amt = abs(amt)                                             # banks export spending as negatives; use magnitude
        key = categorize(r[desc_col])
        totals[key] = totals.get(key, 0.0) + amt                   # merge repeated merchants into one line
    return [
        {"id": str(uuid.uuid4()), "name": label, "amount": f"{total:.2f}", "category": cat}
        for (label, cat), total in sorted(totals.items())
    ]


# Create tables/demo user before anything reads the DB.
init_db()

# ---------------------------------------------------------
# AUTHENTICATION & LANDING SCREEN
# ---------------------------------------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    st.markdown("# 💡 FinPulse")
    st.markdown("### *Your Intelligent Engine for Financial Confidence*")
    st.caption("FNB Challenge Track: Turning information into understanding, understanding into confidence, and confidence into action")
    st.markdown("---")

    auth_tab1, auth_tab2 = st.tabs(["🔑 Sign In", "✨ Create New Account"])

    with auth_tab1:
        st.subheader("Welcome Back")
        st.caption("Demo account: username `alex`, password `password123`")
        login_user = st.text_input("Username", placeholder="e.g. abc123")
        login_pass = st.text_input("Password", type="password", placeholder="••••••••")
        if st.button("Sign In to FinPulse", type="primary"):
            cleaned_user = login_user.lower().strip()
            stored_hash = get_password_hash(cleaned_user)           # None if the user doesn't exist
            if stored_hash and verify_pw(login_pass, stored_hash):  # BOTH must be true to sign in
                start_session(load_user_data(cleaned_user))
                st.rerun()
            else:
                st.error("Invalid username or password.")           # same message either way: don't reveal which was wrong

    with auth_tab2:
        st.subheader("Get Started with FinPulse")
        new_user = st.text_input("Choose Username", placeholder="e.g. abc123")
        new_pass = st.text_input("Choose Password", type="password", placeholder="••••••••")
        new_name = st.text_input("Full Name", placeholder="e.g. David Bumstead")
        new_job = st.text_input("Occupation / Role", placeholder="e.g. Software Engineer")

        if st.button("Create Account & Launch", type="primary"):
            cleaned_username = new_user.lower().strip()
            if cleaned_username and new_pass and new_name:
                if create_new_user(cleaned_username, new_pass, new_name, new_job or "Student"):
                    start_session(load_user_data(cleaned_username))
                    st.rerun()
                else:
                    st.error("Username already exists. Please sign in or pick another username.")
            else:
                st.warning("Please fill out username, password, and full name.")
    st.stop()  # nothing below runs until the user is signed in

# ---------------------------------------------------------
# TOP-BAR & HEADER
# ---------------------------------------------------------
top_col1, top_col2 = st.columns([3, 1])
with top_col1:
    st.markdown("### 💡 FinPulse — FNB Challenge Track")
with top_col2:
    st.markdown(f"👤 **{st.session_state.user_name}** (`{st.session_state.user_job}`)")
    if st.button("🔒 Sign Out"):
        save_user_data()                      # persist before leaving
        for key in list(st.session_state.keys()):
            del st.session_state[key]         # wipe EVERYTHING so the next user can't see leftover data/widget state
        st.rerun()

st.markdown("---")

tab_dash, tab_decide, tab_expenses, tab_report, tab_features = st.tabs([
    "📊 Financial Dashboard",
    "🧭 Can I afford it?",
    "📝 Manage Expenses",
    "📄 Downloadable Report",
    "💡 Project Features & Architecture",
])

# ---------------------------------------------------------
# SHARED CALCULATIONS
# ---------------------------------------------------------
def score_from(income, savings, fixed, disc):
    """Pure scoring function (no Streamlit): used by the dashboard AND the 'Can I afford it?' tab.
    Returns (total_expenses, monthly_surplus, savings_rate_pct, runway_months, confidence_score)."""
    total = fixed + disc                                                         # all monthly spending
    surplus = income - total                                                     # what's left each month
    rate = (surplus / income * 100) if income > 0 else 0.0                       # savings rate in %
    base = fixed if fixed > 0 else total                                         # runway denominator: obligations, else all spending
    runway = (savings / base) if base > 0 else 0.0                               # months of cover
    score = int(min(runway / 6.0 * 40, 40) + min(max(rate, 0) / 30.0 * 60, 60))  # 40 pts runway + 60 pts savings rate
    return total, surplus, rate, runway, score


def compute_metrics():
    """Recompute every number the dashboard and report use from session state."""
    income = max(safe_float(st.session_state.get("monthly_income", 0)), 0.0)    # clamp: no negative income
    savings = max(safe_float(st.session_state.get("current_savings", 0)), 0.0)  # clamp: no negative savings
    fixed = sum(max(safe_float(e["amount"]), 0.0) for e in st.session_state.custom_expenses if e["category"] == "Fixed")
    disc = sum(max(safe_float(e["amount"]), 0.0) for e in st.session_state.custom_expenses if e["category"] == "Discretionary")
    total, surplus, rate, runway, score = score_from(income, savings, fixed, disc)  # shared scoring logic
    return income, savings, fixed, disc, total, surplus, rate, runway, score


parsed_income, parsed_savings, fixed_expenses, discretionary_expenses, total_expenses, \
    monthly_surplus, savings_rate, runway_months, confidence_score = compute_metrics()

# ---------------------------------------------------------
# TAB 1: FINANCIAL DASHBOARD
# ---------------------------------------------------------
with tab_dash:
    ic1, ic2 = st.columns(2)
    inc_val = ic1.text_input("Monthly Take-Home Income ($)", value=str(st.session_state.monthly_income), key="inc_input")
    sav_val = ic2.text_input("Current Emergency Savings ($)", value=str(st.session_state.current_savings), key="sav_input")

    # If the user typed a new value, store it, save, and rerun so every metric refreshes.
    if inc_val != st.session_state.monthly_income:
        st.session_state.monthly_income = inc_val
        save_user_data()
        st.rerun()
    if sav_val != st.session_state.current_savings:
        st.session_state.current_savings = sav_val
        save_user_data()
        st.rerun()

    st.markdown("---")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Monthly Income", f"${parsed_income:,.2f}")
    m2.metric("Total Expenses", f"${total_expenses:,.2f}", delta=f"${monthly_surplus:,.2f} surplus",
              delta_color="normal" if monthly_surplus >= 0 else "inverse")
    m3.metric("Emergency Runway", f"{runway_months:.1f} Mos", delta="Target: 6.0 Mos" if runway_months < 6 else "Safe Buffer")
    m4.metric("Confidence Score", f"{confidence_score} / 100", delta="High Confidence" if confidence_score >= 70 else "Optimization Needed")

    st.markdown("---")

    st.subheader("📈 12-Month Savings Projection")
    st.markdown("See how trimming flexible spending, plus interest, grows your savings over a year.")
    st.info("ℹ️ **How this works:** The first slider tests cutting flexible spending (dining out, trips). "
            "The second sets the yearly interest your savings earn (e.g. a high-yield savings account). "
            "The chart shows your balance each month with and without the cut.")

    sc1, sc2 = st.columns(2)
    optimization_pct = sc1.slider("Optimize discretionary spending by (%):", 0, 50, 15, step=5)
    apy = sc2.slider("Savings interest rate (APY %):", 0.0, 6.0, 4.0, step=0.5)
    monthly_rate = (1 + apy / 100) ** (1 / 12) - 1  # convert APY to the equivalent monthly rate

    optimized_discretionary = discretionary_expenses * (1 - optimization_pct / 100)
    optimized_surplus = parsed_income - (fixed_expenses + optimized_discretionary)


    def project(start, monthly_add):
        """Balance after each of 12 months: grow by interest, then add that month's surplus."""
        balance, out = start, []
        for _ in range(12):
            balance = balance * (1 + monthly_rate) + monthly_add  # true compounding
            out.append(balance)
        return out


    sim_df = pd.DataFrame({
        "Month": list(range(1, 13)),
        "Current Path ($)": project(parsed_savings, monthly_surplus),
        "Optimized Path ($)": project(parsed_savings, optimized_surplus),
    })
    st.line_chart(sim_df.set_index("Month"))
    gain = sim_df["Optimized Path ($)"].iloc[-1] - sim_df["Current Path ($)"].iloc[-1]
    st.caption(f"After 12 months the optimized path is **${gain:,.2f}** ahead of the current path.")

    st.subheader("🎯 Actionable Recommendation")
    if confidence_score >= 75:
        st.success(f"**High Financial Stability:** Your cash flow and emergency buffer are solid. **Next Step:** Direct your **${monthly_surplus:,.2f}** monthly surplus into long-term investments or automated retirement funds.")
    elif confidence_score >= 40:
        st.warning(f"**Moderate Financial Confidence:** Your emergency runway covers **{runway_months:.1f} months**. **Next Step:** Trimming discretionary expenses by **{optimization_pct}%** frees **${(discretionary_expenses - optimized_discretionary):,.2f}** every month.")
    else:
        st.error("**Action Required:** Expenses are near or above income. **Next Step:** Review fixed obligations and subscriptions now to avoid burning through emergency reserves.")

# ---------------------------------------------------------
# TAB: CAN I AFFORD IT? (decision check)
# ---------------------------------------------------------
with tab_decide:
    st.header("🧭 Can I afford it?")
    st.markdown("Test a big purchase or a new monthly bill **before** you commit. "
                "FinPulse shows what it would do to your safety net and score, then gives a plain-language verdict.")

    d1, d2, d3 = st.columns(3)
    dc_item = d1.text_input("What are you considering?", placeholder="e.g. Laptop, car repair, gym", key="dc_item")
    dc_cost = max(safe_float(d2.text_input("Cost ($)", value="1200", key="dc_cost")), 0.0)  # clamp: no negative cost
    dc_kind = d3.selectbox("Type", [
        "One-time purchase (paid from savings)",
        "New monthly bill (flexible)",
        "New monthly bill (fixed obligation)",
    ], key="dc_kind")

    # Start from the user's real numbers, then apply the hypothetical change.
    sav_after, fixed_after, disc_after = parsed_savings, fixed_expenses, discretionary_expenses
    if dc_kind.startswith("One-time"):
        sav_after = parsed_savings - dc_cost                 # paid out of the emergency fund
    elif "flexible" in dc_kind:
        disc_after = discretionary_expenses + dc_cost        # recurring, counts as discretionary
    else:
        fixed_after = fixed_expenses + dc_cost               # recurring, counts as a fixed obligation

    shortfall = sav_after < 0                                # can't pay a one-time cost the savings don't cover
    _, surplus_after, _, runway_after, score_after = score_from(
        parsed_income, max(sav_after, 0.0), fixed_after, disc_after)

    st.markdown("---")
    b1, b2, b3 = st.columns(3)
    b1.metric("Emergency runway", f"{runway_after:.1f} Mos", delta=f"{runway_after - runway_months:+.1f} Mos", delta_color="normal")
    b2.metric("Monthly surplus", f"${surplus_after:,.2f}", delta=f"${surplus_after - monthly_surplus:+,.2f}", delta_color="normal")
    b3.metric("Confidence score", f"{score_after} / 100", delta=f"{score_after - confidence_score:+d}", delta_color="normal")

    label = dc_item.strip() or "This"
    # Verdict rules (rules of thumb chosen for this tool; see caption below).
    if shortfall or surplus_after < 0 or runway_after < 1:
        st.error(f"**Hold off.** {label} would "
                 + ("cost more than your savings." if shortfall else
                    "push you into a monthly deficit." if surplus_after < 0 else
                    "leave less than one month of cover.")
                 + " Build more buffer first or look for a cheaper option.")
    elif runway_after < 3 or score_after < 40 or (confidence_score - score_after) > 15:
        st.warning(f"**Possible, but tighten up first.** {label} leaves you with {runway_after:.1f} months of cover "
                   f"and a score of {score_after}. Consider waiting or trimming flexible spending first.")
    else:
        st.success(f"**Go ahead.** {label} keeps you at {runway_after:.1f} months of cover with a score of {score_after}.")

    if dc_kind.startswith("One-time") and not shortfall and dc_cost > 0 and monthly_surplus > 0:
        st.info(f"At your current surplus you would rebuild this amount in about **{dc_cost / monthly_surplus:.1f} months**.")

    st.caption("Thresholds (3 months of cover, score bands, a 15-point drop) are rules of thumb chosen for this tool, "
               "not regulatory standards. This is not financial advice. All math runs locally on your own entries.")

# ---------------------------------------------------------
# TAB 2: MANAGE EXPENSES
# ---------------------------------------------------------
with tab_expenses:
    st.header("📝 Manage Expenses")

    # --- CSV import ---
    with st.expander("📥 Import a bank statement (CSV)"):
        st.markdown("Upload a CSV with a **description** column and an **amount** column. "
                    "Transactions are auto-categorized and merged into one line per category. "
                    "A sample file is included in the project folder.")
        up = st.file_uploader("Bank statement CSV", type=["csv"], key="csv_upload")
        if up is not None and st.button("Add imported expenses to my budget"):
            try:
                imported = parse_statement(up.getvalue())
                st.session_state.custom_expenses.extend(imported)  # append to the existing budget
                save_user_data()
                st.success(f"Imported {len(imported)} category lines.")
                st.rerun()
            except Exception as err:
                st.error(f"Couldn't read that file: {err}")

    # --- Add one expense ---
    with st.form("unified_add_expense_form", clear_on_submit=True):
        st.subheader("➕ Add New Expense")
        col_f1, col_f2, col_f3 = st.columns(3)
        new_exp_name = col_f1.text_input("Expense Name", placeholder="e.g. Subscriptions, Kids, Trip")
        new_exp_amt = col_f2.text_input("Monthly Amount ($)", placeholder="e.g. 150.00")
        new_exp_cat = col_f3.selectbox("Category Type", ["Fixed", "Discretionary"])
        submitted = st.form_submit_button("Add Expense to Budget")
        if submitted and new_exp_name:
            st.session_state.custom_expenses.append({
                "id": str(uuid.uuid4()),                      # stable ID keeps widget keys unique
                "name": new_exp_name,
                "amount": new_exp_amt or "0.00",
                "category": new_exp_cat,
            })
            save_user_data()
            st.rerun()

    st.markdown("---")
    st.subheader("📋 Active Itemized Expenses")

    if st.session_state.custom_expenses:
        selected_ids, single_delete_id, updated_expenses = [], None, []

        for row in st.session_state.custom_expenses:
            item_id = row["id"]
            col_sel, col_n, col_a, col_c, col_del = st.columns([0.5, 2.5, 2, 2, 1])
            if col_sel.checkbox("Select", key=f"sel_{item_id}", label_visibility="collapsed"):
                selected_ids.append(item_id)
            edited_name = col_n.text_input("Name", value=row["name"], key=f"name_{item_id}", label_visibility="collapsed")
            edited_amt = col_a.text_input("Amount", value=str(row["amount"]), key=f"amt_{item_id}", label_visibility="collapsed")
            edited_cat = col_c.selectbox("Cat", ["Fixed", "Discretionary"], index=0 if row["category"] == "Fixed" else 1,
                                         key=f"cat_{item_id}", label_visibility="collapsed")
            if col_del.button("🗑️", key=f"single_del_{item_id}"):
                single_delete_id = item_id
            updated_expenses.append({"id": item_id, "name": edited_name, "amount": edited_amt, "category": edited_cat})

        # If any edit changed the data, save and rerun so the dashboard numbers refresh immediately.
        if updated_expenses != st.session_state.custom_expenses:
            st.session_state.custom_expenses = updated_expenses
            save_user_data()
            st.rerun()

        if single_delete_id:
            st.session_state.custom_expenses = [e for e in st.session_state.custom_expenses if e["id"] != single_delete_id]
            save_user_data()
            st.rerun()

        btn_col1, btn_col2, _ = st.columns([1, 1, 3])
        if btn_col1.button("🗑️ Delete Selected Items") and selected_ids:
            st.session_state.custom_expenses = [e for e in st.session_state.custom_expenses if e["id"] not in selected_ids]
            save_user_data()
            st.rerun()
        if btn_col2.button("🧹 Clear All Expenses"):
            st.session_state.custom_expenses = []
            save_user_data()
            st.rerun()
    else:
        st.info("No expenses recorded. Use the form or the CSV import above.")

# ---------------------------------------------------------
# TAB 3: DOWNLOADABLE REPORT
# ---------------------------------------------------------
with tab_report:
    st.header("📄 Financial Confidence & Spending Report")
    st.markdown("Use the button inside the report to print it or save it as a PDF.")

    # Generate the report ID once per session so it doesn't change on every rerun.
    if "report_id" not in st.session_state:
        st.session_state.report_id = make_report_id(st.session_state.username)
    esc = html.escape  # shorthand: escape any user-supplied text before it enters the HTML

    rows_html = ""
    for row in st.session_state.custom_expenses:
        tag_cls = "tag-fixed" if row["category"] == "Fixed" else "tag-disc"
        tag_lbl = "Obligation" if row["category"] == "Fixed" else "Variable"
        rows_html += f"""
        <tr>
            <td>{esc(str(row['name']))}</td>
            <td>{esc(str(row['category']))}</td>
            <td><span class="{tag_cls}">{tag_lbl}</span></td>
            <td style="text-align: right; font-weight: 600;">${safe_float(row['amount']):,.2f}</td>
        </tr>"""

    html_report = f"""
    <!DOCTYPE html>
    <html lang="en"><head><meta charset="UTF-8"><style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #1e293b; background: #f8fafc; padding: 20px; }}
        .report-card {{ max-width: 800px; margin: 0 auto; background: #fff; padding: 35px; border-radius: 12px; border: 1px solid #cbd5e1; }}
        .header-bar {{ display: flex; justify-content: space-between; border-bottom: 2px solid #0f172a; padding-bottom: 12px; align-items: center; }}
        .logo-title {{ font-size: 24pt; font-weight: 800; color: #0f172a; margin: 0; }}
        .subtitle {{ font-size: 9pt; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }}
        .profile-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-top: 20px; }}
        .metrics-container {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 20px; }}
        .metric-card {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; }}
        .metric-card.accent {{ background: #f0fdf4; border-color: #bbf7d0; }}
        .metric-val {{ font-size: 14pt; font-weight: 800; color: #0f172a; margin: 4px 0; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 9.5pt; margin-top: 20px; }}
        th {{ background: #f1f5f9; padding: 10px; border-bottom: 1px solid #cbd5e1; text-align: left; color: #334155; }}
        td {{ padding: 9px 10px; border-bottom: 1px solid #e2e8f0; }}
        .tag-fixed {{ background: #eff6ff; color: #1d4ed8; padding: 3px 8px; border-radius: 4px; font-size: 7.5pt; font-weight: 600; }}
        .tag-disc {{ background: #fef2f2; color: #b91c1c; padding: 3px 8px; border-radius: 4px; font-size: 7.5pt; font-weight: 600; }}
        .print-btn {{ background: #0f172a; color: #fff; border: none; padding: 12px 20px; border-radius: 6px; font-weight: 600; cursor: pointer; margin-bottom: 20px; }}
        @media print {{ body {{ background: #fff; padding: 0; }} .report-card {{ border: none; max-width: 100%; padding: 0; }} .print-btn {{ display: none; }} }}
    </style></head>
    <body><div class="report-card">
        <button class="print-btn" onclick="window.print()">🖨️ Print / Save as PDF</button>
        <div class="header-bar">
            <div><h1 class="logo-title">FinPulse</h1><div class="subtitle">Financial Confidence &amp; Spending Report</div></div>
            <div style="text-align: right;"><b>FNB Challenge Track</b><br><small>{datetime.now().strftime('%b %d, %Y')}</small></div>
        </div>
        <div class="profile-grid">
            <div><small style="color:#64748b;font-size:7.5pt;">ACCOUNT HOLDER</small><br><b>{esc(st.session_state.user_name)}</b></div>
            <div><small style="color:#64748b;font-size:7.5pt;">OCCUPATION / ROLE</small><br><b>{esc(st.session_state.user_job)}</b></div>
            <div><small style="color:#64748b;font-size:7.5pt;">REPORT REF</small><br><b>{st.session_state.report_id}</b></div>
        </div>
        <div class="metrics-container">
            <div class="metric-card"><small style="color:#64748b;font-size:7.5pt;">INCOME</small><div class="metric-val">${parsed_income:,.2f}</div></div>
            <div class="metric-card"><small style="color:#64748b;font-size:7.5pt;">EXPENSES</small><div class="metric-val">${total_expenses:,.2f}</div></div>
            <div class="metric-card"><small style="color:#64748b;font-size:7.5pt;">RUNWAY</small><div class="metric-val">{runway_months:.1f} Mos</div></div>
            <div class="metric-card accent"><small style="color:#166534;font-size:7.5pt;">CONFIDENCE</small><div class="metric-val" style="color:#15803d;">{confidence_score} / 100</div></div>
        </div>
        <h3 style="margin-top:25px;font-size:12pt;">Itemized Expenses</h3>
        <table><thead><tr><th>Name</th><th>Category</th><th>Type</th><th style="text-align:right;">Cost</th></tr></thead>
        <tbody>{rows_html}</tbody></table>
    </div></body></html>
    """
    # st.components.v1.html is deprecated in newer Streamlit; prefer st.iframe when available.
    if hasattr(st, "iframe"):
        st.iframe(html_report.strip(), height=750)   # .strip() so it is read as HTML, not a path
    else:
        components.html(html_report, height=750, scrolling=True)
    # Also offer the report as a standalone HTML file download.
    st.download_button("⬇️ Download report (HTML)", data=html_report, file_name="finpulse_report.html", mime="text/html")

# ---------------------------------------------------------
# TAB 4: PROJECT DETAILS
# ---------------------------------------------------------
with tab_features:
    st.header("💡 FinPulse — Architecture & Scoring")
    st.caption("FNB Challenge Track: Trust, Decisions & Financial Confidence")
    st.markdown("---")
    st.markdown("""
    ### **1. Problem**
    Budgeting tools show long tables of past spending, which creates fatigue instead of clarity. **FinPulse** turns a household's numbers into one
    **Financial Confidence Score (0-100)** and a 12-month projection so non-experts can see what a small change in flexible spending does to their safety net.

    ### **2. Architecture**
    * **UI:** Python + Streamlit, with per-session state.
    * **Storage:** local SQLite (`finpulse.db`); expenses are stored as JSON, so categories can change without schema migrations.
    * **Row identity:** each expense has a UUID v4, used in widget keys so edits and batch deletes never hit the wrong row.
    * **Auth:** salted PBKDF2-HMAC-SHA256 password hashes (200k iterations). A production system would add rate limiting and a managed identity provider.
    * **Statement import:** CSV upload, merged into one line per category by keyword rules (no external API calls, so data stays on the machine).

    ### **3. Scoring**
    $$R = \\frac{\\text{Emergency Savings}}{\\text{Fixed Expenses}} \\qquad S = \\frac{\\text{Income} - \\text{Total Expenses}}{\\text{Income}} \\times 100$$
    $$C = \\min\\left(\\frac{R}{6} \\times 40,\\ 40\\right) + \\min\\left(\\frac{\\max(S,0)}{30} \\times 60,\\ 60\\right)$$

    * **Runway (40 pts):** full marks at a 6-month emergency fund, a common rule of thumb.
    * **Savings rate (60 pts):** full marks at saving 30% of income. Weighted higher because ongoing surplus is what builds a buffer.
    * These weights are a design choice, not an industry standard. The score is a guide, not financial advice.

    ### **4. Projection**
    Each month: `balance = balance x (1 + monthly rate) + surplus`, where the monthly rate is derived from the chosen APY.

    ### **5. FNB Alignment**
    * **Information -> understanding:** one score plus plain-language explanations.
    * **Understanding -> confidence:** a what-if slider that shows the effect of a change before committing to it.
    * **Confidence -> action:** a concrete next step by score band, a "Can I afford it?" check that shows the effect of a purchase or new bill before it happens, and a printable report to keep.
    """)
