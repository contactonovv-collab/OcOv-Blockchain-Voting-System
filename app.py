            )

            connection.commit()
            connection.close()

            add_block({
    "election_id": election_id,
    "ballot_hash": ballot_hash
})

            flash("Your vote has been submitted successfully!", "success")
            return redirect(url_for("dashboard"))   

        except Exception as e:

            print("VOTE ERROR:", repr(e))

            connection.rollback()
            connection.close()

            flash("Vote submission failed. Please try again.")
            return redirect(url_for("dashboard"))

    connection.close()

    return render_template(
        "voting.html",
        election=election,
        candidates=candidates
    )

@app.route("/admin/results/<int:election_id>")
def election_results(election_id):
    if "user_id" not in session or session.get("user_role") != "admin":
        return redirect(url_for("login"))

    conn = get_connection()

    election = conn.execute(
        "SELECT * FROM elections WHERE id = ?",
        (election_id,)
    ).fetchone()

    if election is None:
        conn.close()
        return redirect(url_for("admin"))

    # Prevent results from being viewed before the election ends
    if election["end_time"]:
        end_time = datetime.fromisoformat(election["end_time"])

        if now_ist() < end_time:
            conn.close()
            flash("Election results are available only after the election ends.")
            return redirect(url_for("admin"))

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

    total_votes = conn.execute("""
        SELECT COUNT(*) AS total
        FROM ballots
        WHERE election_id = ?
    """, (election_id,)).fetchone()["total"]

    conn.close()

    return render_template(
        "election_results.html",
        election=election,
        results=results,
        total_votes=total_votes
    )
    
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
if __name__ == "__main__":
    app.run(debug=True)
