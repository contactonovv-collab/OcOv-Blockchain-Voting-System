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
@app.route("/temporary-admin-reset", methods=["GET", "POST"])
def temporary_admin_reset():
    if request.method == "POST":
        token = request.form.get("token", "")
        email = request.form.get("email", "").strip().lower()
        new_password = request.form.get("password", "")

        if token != os.environ.get("ADMIN_RESET_TOKEN"):
            return "Invalid reset token", 403

        if len(new_password) < 8:
            return "Password must be at least 8 characters.", 400

        connection = get_connection()

        user = connection.execute(
            "SELECT * FROM users WHERE email = ? AND role = 'admin'",
            (email,)
        ).fetchone()

        if not user:
            connection.execute(
                """
                INSERT INTO users (name, email, roll_number, password_hash, role, email_verified)
                VALUES (?, ?, ?, ?, 'admin', 1)
                """,
                ("OcOv Admin", email, None, generate_password_hash(new_password))
            )
            connection.commit()
            connection.close()
            return "Admin account created successfully. You can now log in."

        connection.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user["id"])
        )

        connection.commit()
        connection.close()

        return "Admin password reset successfully. You can now log in."

    return """
    <form method="POST">
        <input name="token" placeholder="Reset token" required>
        <input name="email" type="email" placeholder="Admin email" required>
        <input name="password" type="password" placeholder="New password" required>
        <button type="submit">Reset Password</button>
    </form>
    """
if __name__ == "__main__":
    app.run(debug=True)
