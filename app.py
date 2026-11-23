import hashlib
import secrets
import json
import os
import uuid
import csv
import io
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from blockchain import add_block, get_blocks, verify_chain

from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session, redirect, url_for, request, abort

from database import initialize_database, get_connection
from email_utils import send_otp_email

app = Flask(__name__)

@app.template_filter('datetime_format')
def datetime_format(value):
    if not value:
        return "Not scheduled"

    try:
        dt = datetime.fromisoformat(str(value))
        return dt.strftime("%d %b %Y · %I:%M %p")
    except (ValueError, TypeError):
        return value
app.secret_key = os.environ.get("SECRET_KEY", "OcOv_local_development_key")

app.config["MAX_CONTENT_LENGTH"] = 3 * 1024 * 1024  # 3 MB

UPLOAD_FOLDER = os.path.join(
    app.static_folder, "uploads", "elections"
)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

initialize_database()


def now_ist():
    """Return current India Standard Time as a naive datetime."""
    return datetime.now(ZoneInfo("Asia/Kolkata")).replace(tzinfo=None)


# Basic blocklist of disposable email domains
DISPOSABLE_DOMAINS = {
    "tempmail.com",
    "10minutemail.com",
    "guerrillamail.com",
    "mailinator.com",
    "yopmail.com",
    "temp-mail.org",
    "throwawaymail.com",
    "getnada.com",
}


def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()


def is_disposable_email(email):
    domain = email.rsplit("@", 1)[-1].lower()
    return domain in DISPOSABLE_DOMAINS


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        roll_number = request.form.get("roll_number", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or not email or not roll_number or not password:
            flash("Please fill in all required fields.")
            return render_template("register.html")

        if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
            flash("Please enter a valid email address.")
            return render_template("register.html")

        if is_disposable_email(email):
            flash("Disposable email addresses are not allowed.")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.")
            return render_template("register.html")

        connection = get_connection()

        existing_user = connection.execute(
            "SELECT id FROM users WHERE email = ? OR roll_number = ?",
            (email, roll_number)
        ).fetchone()

        existing_pending = connection.execute(
            "SELECT id FROM pending_registrations "
            "WHERE email = ? OR roll_number = ?",
            (email, roll_number)
        ).fetchone()

        if existing_user:
            connection.close()
            flash("This email or roll number is already registered.")
            return render_template("register.html")

        if existing_pending:
            connection.close()
            flash(
                "A verification is already pending for these details. "
                "Please verify or restart your registration."
            )
            return render_template("register.html")

        otp = str(secrets.randbelow(900000) + 100000)
        otp_expiry = (datetime.utcnow() + timedelta(minutes=10)).isoformat()

        password_hash = generate_password_hash(password)
        otp_hash_value = hash_otp(otp)

        connection.execute(
            """
            INSERT INTO pending_registrations
            (name, email, roll_number, password_hash, otp_hash, otp_expiry)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (name, email, roll_number, password_hash,
             otp_hash_value, otp_expiry)
        )

        connection.commit()
        connection.close()

        try:
            send_otp_email(email, otp)

        except Exception as e:
            print("EMAIL ERROR:", repr(e))

            connection = get_connection()
            connection.execute(
                "DELETE FROM pending_registrations WHERE email = ?",
                (email,)
            )
            connection.commit()
            connection.close()

            flash("Unable to send verification email. Please try again.")
            return render_template("register.html")

        session["pending_email"] = email
        return redirect(url_for("verify_otp"))

    return render_template("register.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    email = session.get("pending_email")

    if not email:
        flash("Please register first.")
        return redirect(url_for("register"))

    if request.method == "POST":

        otp = request.form.get("otp", "").strip()

        connection = get_connection()

        pending = connection.execute(
            "SELECT * FROM pending_registrations WHERE email = ?",
            (email,)
        ).fetchone()

        if not pending:
            connection.close()
            session.pop("pending_email", None)
            flash("Registration details not found. Please register again.")
            return redirect(url_for("register"))

        if pending["attempts"] >= 5:
            connection.execute(
                "DELETE FROM pending_registrations WHERE email = ?",
                (email,)
            )
            connection.commit()
            connection.close()

            session.pop("pending_email", None)
            flash("Too many attempts. Please register again.")
            return redirect(url_for("register"))

        expiry = datetime.fromisoformat(pending["otp_expiry"])

        if datetime.utcnow() > expiry:
            connection.execute(
                "DELETE FROM pending_registrations WHERE email = ?",
                (email,)
            )
            connection.commit()
            connection.close()

            session.pop("pending_email", None)
            flash("Verification code expired. Please register again.")
            return redirect(url_for("register"))

        if hash_otp(otp) != pending["otp_hash"]:
            connection.execute(
                "UPDATE pending_registrations "
                "SET attempts = attempts + 1 WHERE email = ?",
                (email,)
            )
            connection.commit()
            connection.close()

            flash("Incorrect verification code.")
            return render_template("verify_otp.html")

        cursor = connection.execute(
            """
            INSERT INTO users
            (name, email, roll_number, password_hash, role, email_verified)
            VALUES (?, ?, ?, ?, 'student', 1)
            """,
            (
                pending["name"],
                pending["email"],
                pending["roll_number"],
                pending["password_hash"]
            )
        )

        new_user_id = cursor.lastrowid
        new_user_name = pending["name"]

        connection.execute(
            "DELETE FROM pending_registrations WHERE email = ?",
            (email,)
        )

        connection.commit()
        connection.close()

        session.clear()
        session["user_id"] = new_user_id
        session["user_name"] = new_user_name
        session["user_role"] = "student"

        flash("Email verified! Your account has been created.")
        return redirect(url_for("dashboard"))

    return render_template("verify_otp.html")


@app.route("/resend-otp", methods=["POST"])
def resend_otp():

    email = session.get("pending_email")

    if not email:
        return redirect(url_for("register"))

    connection = get_connection()

    pending = connection.execute(
        "SELECT * FROM pending_registrations WHERE email = ?",
        (email,)
    ).fetchone()

    if not pending:
        connection.close()
        session.pop("pending_email", None)
        return redirect(url_for("register"))

    created_at = datetime.fromisoformat(pending["created_at"])

    if datetime.utcnow() - created_at < timedelta(seconds=60):
        connection.close()
        flash("Please wait 60 seconds before requesting another code.")
        return redirect(url_for("verify_otp"))

    otp = str(secrets.randbelow(900000) + 100000)
    expiry = (datetime.utcnow() + timedelta(minutes=10)).isoformat()

    connection.execute(
        """
        UPDATE pending_registrations
        SET otp_hash = ?, otp_expiry = ?, attempts = 0,
            created_at = CURRENT_TIMESTAMP
        WHERE email = ?
        """,
        (hash_otp(otp), expiry, email)
    )

    connection.commit()
    connection.close()

    try:
        send_otp_email(email, otp)

    except Exception as e:
        print("EMAIL ERROR:", repr(e))
        flash("Unable to send verification email.")

    return redirect(url_for("verify_otp"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        connection = get_connection()

        user = connection.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        connection.close()

        if user and check_password_hash(user["password_hash"], password):

            if not user["email_verified"]:
                flash("Please verify your email before logging in.")
                return render_template("login.html")

            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["user_role"] = user["role"]

            flash("Login successful!")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")
        return render_template("login.html")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("home"))




@app.route("/category/<int:category_id>")
def view_category(category_id):

    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    connection = get_connection()

    category = connection.execute(
        """
        SELECT *
        FROM election_categories
        WHERE id = ? AND enabled = 1
        """,
        (category_id,)
    ).fetchone()

    if not category:
        connection.close()
        flash("Category not found or disabled.")
        return redirect(url_for("dashboard"))

    rows = connection.execute(
        """
        SELECT elections.*,
               election_eligibility.has_voted
        FROM elections
        JOIN election_eligibility
          ON elections.id = election_eligibility.election_id
        WHERE election_eligibility.voter_id = ?
          AND elections.category = ?
        ORDER BY elections.id DESC
        """,
        (session["user_id"], category["name"])
    ).fetchall()

    connection.close()

    now = now_ist()
    elections = []

    for row in rows:

        election = dict(row)

        # Safely parse dates
        try:
            start_time = (
                datetime.fromisoformat(election["start_time"])
                if election["start_time"]
                else None
            )
        except (ValueError, TypeError):
            start_time = None

        try:
            end_time = (
                datetime.fromisoformat(election["end_time"])
                if election["end_time"]
                else None
            )
        except (ValueError, TypeError):
            end_time = None

        election["is_open"] = (
            start_time is not None
            and end_time is not None
            and start_time <= now <= end_time
        )

        election["is_upcoming"] = (
            start_time is not None
            and now < start_time
        )

        election["is_closed"] = (
            end_time is not None
            and now > end_time
        )

        election["date_not_set"] = (
            start_time is None or end_time is None
        )

        election["winner"] = None
        election["is_tie"] = False
        election["winner_candidates"] = []
        election["total_votes"] = 0
        election["results_pending"] = False

        # Winner and results information
        if election["is_closed"]:

            if election["results_declared"]:

                connection = get_connection()

                results = connection.execute(
                    """
                    SELECT candidates.name,
                           candidates.party,
                           COUNT(ballots.id) AS vote_count
                    FROM candidates
                    LEFT JOIN ballots
                        ON candidates.id = ballots.candidate_id
                        AND ballots.election_id = candidates.election_id
                    WHERE candidates.election_id = ?
                    GROUP BY candidates.id, candidates.name, candidates.party
                    ORDER BY vote_count DESC
                    """,
                    (election["id"],)
                ).fetchall()

                total_votes = connection.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM ballots
                    WHERE election_id = ?
                    """,
                    (election["id"],)
                ).fetchone()["total"]

                connection.close()

                election["total_votes"] = total_votes

                if total_votes > 0 and results:

                    highest_votes = results[0]["vote_count"]

                    winner_candidates = [
                        dict(candidate)
                        for candidate in results
                        if candidate["vote_count"] == highest_votes
                    ]

                    if len(winner_candidates) == 1:
                        election["winner"] = winner_candidates[0]

                    elif len(winner_candidates) > 1:
                        election["is_tie"] = True
                        election["winner_candidates"] = winner_candidates

            else:
                election["results_pending"] = True

        elections.append(election)

    # Sort: active, upcoming, undated, ended
    def category_sort_key(election):

        if election["is_open"]:
            priority = 0

        elif election["is_upcoming"]:
            priority = 1

        elif election["date_not_set"]:
            priority = 2

        elif election["is_closed"]:
            priority = 3

        else:
            priority = 2

        return (
            priority,
            election.get("start_time") or ""
        )

    elections.sort(key=category_sort_key)

    return render_template(
        "category_elections.html",
        category=category,
        elections=elections
    )

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    connection = get_connection()

    # Fetch elections assigned to this student
    rows = connection.execute(
        """
        SELECT elections.*,
               election_eligibility.has_voted
        FROM elections
        JOIN election_eligibility
          ON elections.id = election_eligibility.election_id
        WHERE election_eligibility.voter_id = ?
        ORDER BY elections.id DESC
        """,
        (session["user_id"],)
    ).fetchall()

    # Fetch enabled categories for the dashboard
    categories = connection.execute(
        """
        SELECT *
        FROM election_categories
        WHERE enabled = 1
        ORDER BY id
        """
    ).fetchall()

    connection.close()

    now = now_ist()
    elections = []

    for row in rows:

        election = dict(row)

        # Handle missing dates safely
        try:
            start_time = (
                datetime.fromisoformat(election["start_time"])
                if election["start_time"]
                else None
            )
        except (ValueError, TypeError):
            start_time = None

        try:
            end_time = (
                datetime.fromisoformat(election["end_time"])
                if election["end_time"]
                else None
            )
        except (ValueError, TypeError):
            end_time = None

        election["is_open"] = (
            start_time is not None
            and end_time is not None
            and start_time <= now <= end_time
        )

        election["is_upcoming"] = (
            start_time is not None
            and now < start_time
        )

        election["is_closed"] = (
            end_time is not None
            and now > end_time
        )

        election["date_not_set"] = (
            start_time is None or end_time is None
        )

        # Winner information
        election["winner"] = None
        election["is_tie"] = False
        election["winner_candidates"] = []
        election["total_votes"] = 0
        election["results_pending"] = False

        if election["is_closed"]:

            if election["results_declared"]:

                connection = get_connection()

                results = connection.execute(
                    """
                    SELECT candidates.name,
                           candidates.party,
                           COUNT(ballots.id) AS vote_count
                    FROM candidates
                    LEFT JOIN ballots
                        ON candidates.id = ballots.candidate_id
                        AND ballots.election_id = candidates.election_id
                    WHERE candidates.election_id = ?
                    GROUP BY candidates.id, candidates.name, candidates.party
                    ORDER BY vote_count DESC
                    """,
                    (election["id"],)
                ).fetchall()

                total_votes = connection.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM ballots
                    WHERE election_id = ?
                    """,
                    (election["id"],)
                ).fetchone()["total"]

                connection.close()

                election["total_votes"] = total_votes

                if total_votes > 0 and results:

                    highest_votes = results[0]["vote_count"]

                    winner_candidates = [
                        dict(candidate)
                        for candidate in results
                        if candidate["vote_count"] == highest_votes
                    ]

                    if len(winner_candidates) == 1:
                        election["winner"] = winner_candidates[0]

                    elif len(winner_candidates) > 1:
                        election["is_tie"] = True
                        election["winner_candidates"] = winner_candidates

            else:
                election["results_pending"] = True

        # Assign sorting priority
        if election["is_open"]:
            election["sort_priority"] = 0

        elif election["is_upcoming"]:

            time_until_start = start_time - now

            if time_until_start <= timedelta(hours=24):
                election["sort_priority"] = 1

            elif time_until_start <= timedelta(days=30):
                election["sort_priority"] = 2

            else:
                election["sort_priority"] = 3

        elif election["date_not_set"]:
            election["sort_priority"] = 4

        elif election["is_closed"]:
            election["sort_priority"] = 5

        else:
            election["sort_priority"] = 4

        elections.append(election)

    # Sort elections by priority, then by nearest start time
    elections.sort(
        key=lambda election: (
            election["sort_priority"],
            election.get("start_time") or ""
        )
    )

    return render_template(
        "dashboard.html",
        elections=elections,
        categories=categories
    )

@app.route("/admin", methods=["GET", "POST"])
def admin():

    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    if session.get("user_role") != "admin":
        flash("Access denied.")
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        start_time = request.form.get("start_time", "").strip()
        end_time = request.form.get("end_time", "").strip()
        category = request.form.get("category", "").strip()
        image = request.files.get("thumbnail")

        if not title or not start_time or not end_time or not category:
            flash("Please fill in the election title, category and dates.")

        else:
            try:
                start_date = datetime.fromisoformat(start_time)
                end_date = datetime.fromisoformat(end_time)

                if end_date <= start_date:
                    flash("Election end time must be after its start time.")

                else:
                    connection = get_connection()

                    valid_category = connection.execute(
                        """
                        SELECT name FROM election_categories
                        WHERE name = ? AND enabled = 1
                        """,
                        (category,)
                    ).fetchone()

                    connection.close()

                    if not valid_category:
                        flash("Please select a valid election category.")

                    else:
                        thumbnail_filename = None
                        image_valid = True

                        if image and image.filename:

                            original_filename = secure_filename(image.filename)

                            if "." not in original_filename:
                                image_valid = False
                            else:
                                extension = original_filename.rsplit(".", 1)[-1].lower()

                                if extension not in ALLOWED_IMAGE_EXTENSIONS:
                                    image_valid = False
                                else:
                                    thumbnail_filename = (
                                        uuid.uuid4().hex + "." + extension
                                    )

                        if not image_valid:
                            flash("Please upload a JPG, JPEG, PNG or WEBP image.")

                        else:

                            if image and image.filename and thumbnail_filename:
                                image.save(
                                    os.path.join(
                                        UPLOAD_FOLDER,
                                        thumbnail_filename
                                    )
                                )

                            connection = get_connection()

                            connection.execute(
                                """
                                INSERT INTO elections
                                (title, description, start_time, end_time,
                                 thumbnail, category)
                                VALUES (?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    title,
                                    description,
                                    start_time,
                                    end_time,
                                    thumbnail_filename,
                                    category
                                )
                            )

                            connection.commit()
                            connection.close()

                            flash("Election created successfully!")
                            return redirect(url_for("admin"))

            except ValueError:
                flash("Please enter valid election dates.")

    # Load election management data
    connection = get_connection()

    categories = connection.execute(
        """
        SELECT * FROM election_categories
        WHERE enabled = 1
        ORDER BY name
        """
    ).fetchall()

    elections = connection.execute(
        """
        SELECT
            e.*,
            (
                SELECT COUNT(*)
                FROM election_eligibility ee
                WHERE ee.election_id = e.id
            ) AS eligible_count,
            (
                SELECT COUNT(*)
                FROM ballots b
                WHERE b.election_id = e.id
            ) AS votes_count
        FROM elections e
        ORDER BY e.id DESC
        """
    ).fetchall()

    elections = [dict(election) for election in elections]

    for election in elections:
        election["turnout"] = (
            round(
                (election["votes_count"] / election["eligible_count"]) * 100,
                2
            )
            if election["eligible_count"] > 0
            else 0
        )

    total_students = connection.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'student' AND email_verified = 1"
    ).fetchone()[0]

    total_elections = connection.execute(
        "SELECT COUNT(*) FROM elections"
    ).fetchone()[0]

    total_eligible_voters = connection.execute(
        "SELECT COUNT(*) FROM election_eligibility"
    ).fetchone()[0]

    total_votes_cast = connection.execute(
        "SELECT COUNT(*) FROM ballots"
    ).fetchone()[0]

    voter_turnout = (
        (total_votes_cast / total_eligible_voters) * 100
        if total_eligible_voters > 0
        else 0
    )

    connection.close()

    return render_template(
        "admin.html",
        elections=elections,
        categories=categories,
        total_students=total_students,
        total_elections=total_elections,
        total_eligible_voters=total_eligible_voters,
        total_votes_cast=total_votes_cast,
        voter_turnout=voter_turnout
    )

@app.route("/admin/categories", methods=["GET", "POST"])
def manage_categories():

    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    if session.get("user_role") != "admin":
        flash("Access denied.")
        return redirect(url_for("dashboard"))

    category_upload_folder = os.path.join(
        app.static_folder, "uploads", "categories"
    )
    os.makedirs(category_upload_folder, exist_ok=True)

    if request.method == "POST":

        action = request.form.get("action", "create")

        connection = get_connection()

        if action == "toggle":
            category_id = request.form.get("category_id")

            category = connection.execute(
                "SELECT * FROM election_categories WHERE id = ?",
                (category_id,)
            ).fetchone()

            if category:
                new_status = 0 if category["enabled"] else 1

                connection.execute(
                    "UPDATE election_categories SET enabled = ? WHERE id = ?",
                    (new_status, category_id)
                )

                connection.commit()
                flash("Category status updated.")

            connection.close()
            return redirect(url_for("manage_categories"))

        if action == "create":

            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()
            image = request.files.get("image")

            if not name:
                connection.close()
                flash("Category name is required.")
                return redirect(url_for("manage_categories"))

            existing = connection.execute(
                "SELECT id FROM election_categories WHERE name = ?",
                (name,)
            ).fetchone()

            if existing:
                connection.close()
                flash("A category with this name already exists.")
                return redirect(url_for("manage_categories"))

            image_filename = None

            if image and image.filename:

                original_filename = secure_filename(image.filename)

                if "." not in original_filename:
                    connection.close()
                    flash("Invalid image file.")
                    return redirect(url_for("manage_categories"))

                extension = original_filename.rsplit(".", 1)[-1].lower()

                if extension not in ALLOWED_IMAGE_EXTENSIONS:
                    connection.close()
                    flash("Please upload a JPG, JPEG, PNG or WEBP image.")
                    return redirect(url_for("manage_categories"))

                image_filename = uuid.uuid4().hex + "." + extension

                image.save(
                    os.path.join(
                        category_upload_folder,
                        image_filename
                    )
                )

            connection.execute(
                """
                INSERT INTO election_categories
                (name, description, image, enabled)
                VALUES (?, ?, ?, 1)
                """,
                (name, description, image_filename)
            )

            connection.commit()
            connection.close()

            flash("Category created successfully!")
            return redirect(url_for("manage_categories"))

        connection.close()

    connection = get_connection()

    categories = connection.execute(
        """
        SELECT *
        FROM election_categories
        ORDER BY id
        """
    ).fetchall()

    connection.close()

    return render_template(
        "category_management.html",
        categories=categories
    )


@app.route("/admin/candidates", methods=["GET", "POST"])
def manage_candidates():

    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    if session.get("user_role") != "admin":
        flash("Access denied.")
        return redirect(url_for("dashboard"))

    connection = get_connection()

    if request.method == "POST":

        election_id = request.form.get("election_id")
        name = request.form.get("name", "").strip()
        party = request.form.get("party", "").strip()
        description = request.form.get("description", "").strip()

        if not election_id or not name:
            flash("Please select an election and enter a candidate name.")

        else:
            election = connection.execute(
                "SELECT id FROM elections WHERE id = ?",
                (election_id,)
            ).fetchone()

            if not election:
                flash("Selected election does not exist.")

            else:
                connection.execute(
                    """
                    INSERT INTO candidates
                    (election_id, name, party, description)
                    VALUES (?, ?, ?, ?)
                    """,
                    (election_id, name, party, description)
                )

                connection.commit()
                flash("Candidate added successfully!")

    elections = connection.execute(
    """
    SELECT elections.*,
        (SELECT COUNT(*)
         FROM election_eligibility
         WHERE election_id = elections.id) AS eligible_count,

        (SELECT COUNT(*)
         FROM ballots
         WHERE election_id = elections.id) AS votes_count

    FROM elections
    ORDER BY elections.id DESC
    """
).fetchall()

    elections = [dict(election) for election in elections]

    for election in elections:
        eligible = election["eligible_count"]
        votes = election["votes_count"]

        election["turnout"] = (
        (votes / eligible) * 100 if eligible > 0 else 0
        )

        candidates = connection.execute(
        """
        SELECT candidates.*, elections.title AS election_title
        FROM candidates
        JOIN elections ON candidates.election_id = elections.id
        ORDER BY candidates.id DESC
        """
        ).fetchall()

    connection.close()

    return render_template(
        "candidate_management.html",
        elections=elections,
        candidates=candidates
    )


@app.route("/admin/eligibility", methods=["GET", "POST"])
def manage_eligibility():

    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    if session.get("user_role") != "admin":
        flash("Access denied.")
        return redirect(url_for("dashboard"))

    connection = get_connection()

    # Handle assigning students to an election
    if request.method == "POST":

        election_id = request.form.get("election_id")
        voter_ids = request.form.getlist("voter_ids")

        if not election_id:
            flash("Please select an election.")

        elif not voter_ids:
            flash("Please select at least one student.")

        else:
            # Confirm the election exists
            election = connection.execute(
                "SELECT id FROM elections WHERE id = ?",
                (election_id,)
            ).fetchone()

            if not election:
                flash("Invalid election selected.")

            else:
                assigned_count = 0

                for voter_id in voter_ids:

                    # Only verified student accounts can be assigned
                    student = connection.execute(
                        """
                        SELECT id
                        FROM users
                        WHERE id = ?
                        AND role = 'student'
                        AND email_verified = 1
                        """,
                        (voter_id,)
                    ).fetchone()

                    if student:
                        cursor = connection.execute(
                            """
                            INSERT OR IGNORE INTO election_eligibility
                            (election_id, voter_id, has_voted)
                            VALUES (?, ?, 0)
                            """,
                            (election_id, voter_id)
                        )

                        if cursor.rowcount > 0:
                            assigned_count += 1

                connection.commit()

                flash(
                    f"{assigned_count} student(s) successfully assigned. "
                    "Already assigned students were skipped."
                )

        connection.close()
        return redirect(url_for("manage_eligibility"))

    # Fetch elections
    elections = connection.execute(
        """
        SELECT *
        FROM elections
        ORDER BY id DESC
        """
    ).fetchall()

    # Fetch verified student accounts
    students = connection.execute(
        """
        SELECT id, name, email, roll_number
        FROM users
        WHERE role = 'student'
        AND email_verified = 1
        ORDER BY name ASC
        """
    ).fetchall()

    # Fetch eligibility records with student and election details
    eligibility = connection.execute(
        """
        SELECT
            users.name,
            users.email,
            users.roll_number,
            elections.title AS election_title,
            election_eligibility.has_voted

        FROM election_eligibility

        JOIN users
            ON users.id = election_eligibility.voter_id

        JOIN elections
            ON elections.id = election_eligibility.election_id

        ORDER BY elections.id DESC, users.name ASC
        """
    ).fetchall()

    # Dashboard statistics
    total_students = connection.execute(
        """
        SELECT COUNT(*)
        FROM users
        WHERE role = 'student'
        AND email_verified = 1
        """
    ).fetchone()[0]

    total_elections = connection.execute(
        "SELECT COUNT(*) FROM elections"
    ).fetchone()[0]

    total_eligible_voters = connection.execute(
        "SELECT COUNT(*) FROM election_eligibility"
    ).fetchone()[0]

    total_votes_cast = connection.execute(
        "SELECT COUNT(*) FROM ballots"
    ).fetchone()[0]

    voter_turnout = (
        (total_votes_cast / total_eligible_voters) * 100
        if total_eligible_voters > 0
        else 0
    )

    connection.close()

    return render_template(
        "eligibility_management.html",
        elections=elections,
        students=students,
        eligibility=eligibility,
        total_students=total_students,
        total_elections=total_elections,
        total_eligible_voters=total_eligible_voters,
        total_votes_cast=total_votes_cast,
        voter_turnout=voter_turnout
    )


@app.route("/vote/<int:election_id>", methods=["GET", "POST"])
def vote(election_id):

    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    connection = get_connection()

    try:

        election = connection.execute(
            "SELECT * FROM elections WHERE id = ?",
            (election_id,)
        ).fetchone()

        if not election:
            flash("Election not found.")
            return redirect(url_for("dashboard"))

        eligibility = connection.execute(
            """
            SELECT * FROM election_eligibility
            WHERE election_id = ? AND voter_id = ?
            """,
            (election_id, session["user_id"])
        ).fetchone()

        if not eligibility:
            flash("You are not eligible for this election.")
            return redirect(url_for("dashboard"))

        if eligibility["has_voted"]:
            flash("You have already voted in this election.")
            return redirect(url_for("dashboard"))

        try:
            start_time = datetime.fromisoformat(election["start_time"])
            end_time = datetime.fromisoformat(election["end_time"])
        except (ValueError, TypeError):
            flash("Election schedule is invalid.")
            return redirect(url_for("dashboard"))

        now = now_ist()

        if now < start_time or now > end_time:
            flash("This election is not currently open for voting.")
            return redirect(url_for("dashboard"))

        candidates = connection.execute(
            "SELECT * FROM candidates WHERE election_id = ?",
            (election_id,)
        ).fetchall()

        if request.method == "POST":

            candidate_id = request.form.get("candidate_id")

            candidate = connection.execute(
                """
                SELECT id FROM candidates
                WHERE id = ? AND election_id = ?
                """,
                (candidate_id, election_id)
            ).fetchone()

            if not candidate:
                flash("Invalid candidate selection.")
                return redirect(url_for("vote", election_id=election_id))

            connection.execute("BEGIN IMMEDIATE")

            current_eligibility = connection.execute(
                """
                SELECT has_voted FROM election_eligibility
                WHERE election_id = ? AND voter_id = ?
                """,
                (election_id, session["user_id"])
            ).fetchone()

            if not current_eligibility or current_eligibility["has_voted"]:

                connection.rollback()

                flash("You have already voted or are not eligible.")
                return redirect(url_for("dashboard"))

            # Recheck election timing inside the transaction
            current_election = connection.execute(
                "SELECT start_time, end_time FROM elections WHERE id = ?",
                (election_id,)
            ).fetchone()

            try:
                current_start = datetime.fromisoformat(
                    current_election["start_time"]
                )
                current_end = datetime.fromisoformat(
                    current_election["end_time"]
                )
            except (ValueError, TypeError):
                connection.rollback()
                flash("Election schedule is invalid.")
                return redirect(url_for("dashboard"))

            current_now = now_ist()

            if current_now < current_start or current_now > current_end:
                connection.rollback()
                flash("This election is no longer open for voting.")
                return redirect(url_for("dashboard"))

            ballot_nonce = secrets.token_hex(16)

            ballot_data = (
                str(election_id) + "|" +
                str(candidate_id) + "|" +
                ballot_nonce
            )

            ballot_hash = hashlib.sha256(
                ballot_data.encode()
            ).hexdigest()

            connection.execute(
                """
                INSERT INTO ballots
                (election_id, candidate_id, ballot_hash)
                VALUES (?, ?, ?)
                """,
                (election_id, candidate_id, ballot_hash)
            )

            connection.execute(
                """
                INSERT INTO voting_receipts
                (election_id, voter_id)
                VALUES (?, ?)
                """,
                (election_id, session["user_id"])
            )

            connection.execute(
                """
                UPDATE election_eligibility
                SET has_voted = 1
                WHERE election_id = ? AND voter_id = ?
                """,
                (election_id, session["user_id"])
            )

            connection.commit()

            add_block({
                "election_id": election_id,
                "ballot_hash": ballot_hash
            })

            flash("Your vote has been submitted successfully!", "success")
            return redirect(url_for("dashboard"))

        return render_template(
            "voting.html",
            election=election,
            candidates=candidates
        )

    except Exception as e:

        print("VOTE ERROR:", repr(e))

        if connection.in_transaction:
            connection.rollback()

        flash("Vote submission failed. Please try again.")
        return redirect(url_for("dashboard"))

    finally:
        connection.close()

@app.route("/admin/results/<int:election_id>")
def election_results(election_id):

    if "user_id" not in session or session.get("user_role") != "admin":
        return redirect(url_for("login"))

    conn = get_connection()

    try:

        election = conn.execute(
            "SELECT * FROM elections WHERE id = ?",
            (election_id,)
        ).fetchone()

        if election is None:
            flash("Election not found.")
            return redirect(url_for("admin"))

        # Prevent results from being viewed before the election ends
        if election["end_time"]:

            try:
                end_time = datetime.fromisoformat(election["end_time"])
            except (ValueError, TypeError):
                flash("Invalid election end date.")
                return redirect(url_for("admin"))

            if now_ist() < end_time:
                flash("Election results are available only after the election ends.")
                return redirect(url_for("admin"))

        # Candidate results
        results = conn.execute("""
            SELECT
                candidates.id,
                candidates.name,
                candidates.party,
                COUNT(ballots.id) AS vote_count
            FROM candidates
            LEFT JOIN ballots
                ON candidates.id = ballots.candidate_id
                AND ballots.election_id = candidates.election_id
            WHERE candidates.election_id = ?
            GROUP BY candidates.id, candidates.name, candidates.party
            ORDER BY vote_count DESC
        """, (election_id,)).fetchall()

        # Total ballots
        total_votes = conn.execute("""
            SELECT COUNT(*) AS total
            FROM ballots
            WHERE election_id = ?
        """, (election_id,)).fetchone()["total"]

        # Voter turnout analytics
        eligible_voters = conn.execute("""
            SELECT COUNT(*) AS total
            FROM election_eligibility
            WHERE election_id = ?
        """, (election_id,)).fetchone()["total"]

        votes_cast = conn.execute("""
            SELECT COUNT(*) AS total
            FROM election_eligibility
            WHERE election_id = ?
            AND has_voted = 1
        """, (election_id,)).fetchone()["total"]

        non_voters = max(eligible_voters - votes_cast, 0)

        turnout_percentage = (
            (votes_cast / eligible_voters) * 100
            if eligible_voters > 0
            else 0
        )

    finally:
        conn.close()

    # Determine winner or tie
    winner_candidates = []

    if total_votes > 0 and results:
        highest_votes = results[0]["vote_count"]

        winner_candidates = [
            candidate for candidate in results
            if candidate["vote_count"] == highest_votes
        ]

    winner = None
    is_tie = False

    if total_votes > 0:

        if len(winner_candidates) == 1:
            winner = winner_candidates[0]

        elif len(winner_candidates) > 1:
            is_tie = True

    # Winner margin analytics
    runner_up_votes = results[1]["vote_count"] if len(results) > 1 else 0

    if total_votes == 0:

        winner_margin = 0
        winner_margin_percentage = 0
        competition_level = "No votes"

    elif is_tie:

        winner_margin = 0
        winner_margin_percentage = 0
        competition_level = "Tie"

    elif len(results) == 1:

        winner_margin = results[0]["vote_count"]

        winner_margin_percentage = (
            (winner_margin / total_votes) * 100
            if total_votes > 0 else 0
        )

        competition_level = "No competition"

    else:

        winner_margin = winner_candidates[0]["vote_count"] - runner_up_votes

        winner_margin_percentage = (
            (winner_margin / total_votes) * 100
            if total_votes > 0 else 0
        )

        if winner_margin_percentage <= 5:
            competition_level = "Very Close"

        elif winner_margin_percentage <= 15:
            competition_level = "Competitive"

        else:
            competition_level = "Clear Win"

    return render_template(
        "election_results.html",
        election=election,
        results=results,
        total_votes=total_votes,
        winner=winner,
        winner_candidates=winner_candidates,
        is_tie=is_tie,
        eligible_voters=eligible_voters,
        votes_cast=votes_cast,
        non_voters=non_voters,
        turnout_percentage=turnout_percentage,
        runner_up_votes=runner_up_votes,
        winner_margin=winner_margin,
        winner_margin_percentage=winner_margin_percentage,
        competition_level=competition_level
    )
@app.route("/admin/results/<int:election_id>/export")
def export_election_results(election_id):

    if "user_id" not in session or session.get("user_role") != "admin":
        return redirect(url_for("login"))

    conn = get_connection()

    election = conn.execute(
        "SELECT * FROM elections WHERE id = ?",
        (election_id,)
    ).fetchone()

    if not election:
        conn.close()
        flash("Election not found.")
        return redirect(url_for("admin"))

    # Prevent export before election ends
    if election["end_time"]:
        end_time = datetime.fromisoformat(election["end_time"])

        if now_ist() < end_time:
            conn.close()
            flash("Election report is available only after the election ends.")
            return redirect(url_for("admin"))

    results = conn.execute("""
        SELECT
            candidates.name,
            candidates.party,
            COUNT(ballots.id) AS vote_count
        FROM candidates
        LEFT JOIN ballots
            ON candidates.id = ballots.candidate_id
            AND ballots.election_id = candidates.election_id
        WHERE candidates.election_id = ?
        GROUP BY candidates.id, candidates.name, candidates.party
        ORDER BY vote_count DESC
    """, (election_id,)).fetchall()

    total_votes = conn.execute(
        "SELECT COUNT(*) FROM ballots WHERE election_id = ?",
        (election_id,)
    ).fetchone()[0]

    eligible_voters = conn.execute(
        "SELECT COUNT(*) FROM election_eligibility WHERE election_id = ?",
        (election_id,)
    ).fetchone()[0]

    votes_cast = conn.execute(
        """
        SELECT COUNT(*)
        FROM election_eligibility
        WHERE election_id = ?
        AND has_voted = 1
        """,
        (election_id,)
    ).fetchone()[0]

    conn.close()

    non_voters = max(eligible_voters - votes_cast, 0)

    turnout_percentage = (
        votes_cast / eligible_voters * 100
        if eligible_voters > 0 else 0
    )

    # Winner and tie calculation
    winner_candidates = []

    if total_votes > 0 and results:
        highest_votes = results[0]["vote_count"]

        winner_candidates = [
            candidate for candidate in results
            if candidate["vote_count"] == highest_votes
        ]

    winner = None
    is_tie = False

    if total_votes > 0:
        if len(winner_candidates) == 1:
            winner = winner_candidates[0]
        elif len(winner_candidates) > 1:
            is_tie = True

    runner_up_votes = results[1]["vote_count"] if len(results) > 1 else 0

    if total_votes == 0:
        winner_margin = 0
        winner_margin_percentage = 0
        competition_level = "No votes"

    elif is_tie:
        winner_margin = 0
        winner_margin_percentage = 0
        competition_level = "Tie"

    elif len(results) == 1:
        winner_margin = results[0]["vote_count"]
        winner_margin_percentage = (
            winner_margin / total_votes * 100
        )
        competition_level = "No competition"

    else:
        winner_margin = winner_candidates[0]["vote_count"] - runner_up_votes

        winner_margin_percentage = (
            winner_margin / total_votes * 100
        )

        if winner_margin_percentage <= 5:
            competition_level = "Very Close"
        elif winner_margin_percentage <= 15:
            competition_level = "Competitive"
        else:
            competition_level = "Clear Win"

    winner_name = (
        winner["name"] if winner else
        "Tie" if is_tie else "No winner"
    )

    # Generate CSV
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["OcOv - Election Report"])
    writer.writerow(["Election", election["title"]])
    writer.writerow(["Description", election["description"] or ""])
    writer.writerow(["Results Declared", "Yes" if election["results_declared"] else "No"])
    writer.writerow([])

    writer.writerow(["Election Statistics"])
    writer.writerow(["Eligible Voters", eligible_voters])
    writer.writerow(["Votes Cast", votes_cast])
    writer.writerow(["Non-Voters", non_voters])
    writer.writerow(["Total Ballots", total_votes])
    writer.writerow(["Turnout Percentage", f"{turnout_percentage:.2f}%"])
    writer.writerow([])

    writer.writerow(["Winner Analysis"])
    writer.writerow(["Winner / Outcome", winner_name])
    writer.writerow(["Winning Margin", winner_margin])
    writer.writerow(["Margin Percentage", f"{winner_margin_percentage:.2f}%"])
    writer.writerow(["Competition Level", competition_level])
    writer.writerow([])

    writer.writerow(["Candidate Results"])
    writer.writerow(["Candidate Name", "Party", "Votes", "Vote Share"])

    for candidate in results:
        vote_percentage = (
            candidate["vote_count"] / total_votes * 100
            if total_votes > 0 else 0
        )

        writer.writerow([
            candidate["name"],
            candidate["party"] or "",
            candidate["vote_count"],
            f"{vote_percentage:.2f}%"
        ])

    response = make_response(output.getvalue())

    response.headers["Content-Disposition"] = (
        f'attachment; filename="election_{election_id}_report.csv"'
    )
    response.headers["Content-Type"] = "text/csv; charset=utf-8"

    return response

@app.route("/admin/declare-results/<int:election_id>", methods=["POST"])
def declare_results(election_id):

    if "user_id" not in session or session.get("user_role") != "admin":
        return redirect(url_for("login"))

    conn = get_connection()

    election = conn.execute(
        "SELECT * FROM elections WHERE id = ?",
        (election_id,)
    ).fetchone()

    if election is None:
        conn.close()
        flash("Election not found.")
        return redirect(url_for("admin"))

    if election["end_time"]:
        end_time = datetime.fromisoformat(election["end_time"])

        if now_ist() < end_time:
            conn.close()
            flash("Results cannot be declared before the election ends.")
            return redirect(url_for("election_results", election_id=election_id))

    if election["results_declared"]:
        conn.close()
        flash("Results have already been declared.")
        return redirect(url_for("election_results", election_id=election_id))

    total_votes = conn.execute(
        "SELECT COUNT(*) AS total FROM ballots WHERE election_id = ?",
        (election_id,)
    ).fetchone()["total"]

    if total_votes == 0:
        conn.close()
        flash("Results cannot be declared because no votes were recorded.")
        return redirect(url_for("election_results", election_id=election_id))

    conn.execute(
        "UPDATE elections SET results_declared = 1 WHERE id = ?",
        (election_id,)
    )

    conn.commit()
    conn.close()

    flash("Election results have been officially declared.")

    return redirect(url_for("election_results", election_id=election_id))

@app.route("/admin/blockchain")
def blockchain_view():

    if "user_id" not in session or session.get("user_role") != "admin":
        return redirect(url_for("login"))

    blocks = get_blocks()
    chain_valid = verify_chain()

    return render_template(
        "blockchain.html",
        blocks=blocks,
        chain_valid=chain_valid
    )
    
@app.route("/audit/<int:election_id>")
def election_audit(election_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_connection()

    election = conn.execute(
        "SELECT * FROM elections WHERE id = ?",
        (election_id,)
    ).fetchone()

    if election is None:
        conn.close()
        flash("Election not found.")
        return redirect(url_for("dashboard"))

    if not election["results_declared"]:
        conn.close()
        flash("Audit information is available only after results are declared.")
        return redirect(url_for("dashboard"))

    eligibility = conn.execute(
        """
        SELECT id FROM election_eligibility
        WHERE election_id = ? AND voter_id = ?
        """,
        (election_id, session["user_id"])
    ).fetchone()

    if session.get("user_role") == "student" and eligibility is None:
        conn.close()
        flash("You are not eligible to view this election.")
        return redirect(url_for("dashboard"))

    total_votes = conn.execute(
        "SELECT COUNT(*) AS total FROM ballots WHERE election_id = ?",
        (election_id,)
    ).fetchone()["total"]

    conn.close()

    blocks = get_blocks()
    chain_valid = verify_chain()

    election_blocks = []

    for block in blocks:
        try:
            block_data = json.loads(block["data"])

            if block_data.get("election_id") == election_id:
                election_blocks.append(block)

        except (json.JSONDecodeError, TypeError):
            continue

    return render_template(
        "election_audit.html",
        election=election,
        total_votes=total_votes,
        chain_valid=chain_valid,
        election_blocks=election_blocks
    )

@app.route("/temporary-demo-admin")
def temporary_demo_admin():
    token = request.args.get("token", "")

    if not token or token != os.environ.get("DEMO_ADMIN_TOKEN"):
        abort(403)

    connection = get_connection()
    admin = connection.execute(
        "SELECT * FROM users WHERE role = 'admin' LIMIT 1"
    ).fetchone()
    connection.close()

    if not admin:
        return "No admin account exists in the database.", 404

    session.clear()
    session["user_id"] = admin["id"]
    session["user_name"] = admin["name"]
    session["user_role"] = "admin"

    return redirect(url_for("admin"))
    
if __name__ == "__main__":
    app.run(debug=True)
