from flask import Flask, render_template, request, redirect, url_for, session, send_file
import csv
import io

app = Flask(__name__)
app.secret_key = "cyberrisk-demo-secret-key"


# -------------------------------------------------
# Demo Login Credentials
# -------------------------------------------------

USERNAME = "admin"
PASSWORD = "admin123"


# -------------------------------------------------
# Temporary Finding Storage
# -------------------------------------------------

findings = []


# -------------------------------------------------
# GRC Recommendations
# -------------------------------------------------

recommendations = {
    "Open SSH Port":
        "Restrict SSH access to authorized users and trusted networks. "
        "Disable SSH if remote access is not required.",

    "HTTP Service Exposed":
        "Review the web service configuration and use HTTPS where applicable. "
        "Restrict unnecessary external exposure.",

    "Service Version Disclosure":
        "Minimize unnecessary service and version information disclosure "
        "to reduce information leakage.",

    "Unnecessary Service":
        "Disable or remove services that are not required for business operations.",

    "Weak Security Configuration":
        "Review the configuration against organizational security policies "
        "and apply appropriate security controls."
}


# -------------------------------------------------
# Risk Calculation
# -------------------------------------------------

def calculate_risk(likelihood, impact):

    score = likelihood * impact

    if score <= 4:
        level = "LOW"
    elif score <= 9:
        level = "MEDIUM"
    elif score <= 16:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return score, level


# -------------------------------------------------
# Login Page
# -------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if username == USERNAME and password == PASSWORD:

            session["logged_in"] = True

            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            error="Invalid username or password."
        )

    return render_template("login.html")


# -------------------------------------------------
# Dashboard
# -------------------------------------------------

@app.route("/dashboard")
def dashboard():

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    total = len(findings)

    high = sum(
        1 for finding in findings
        if finding["risk_level"] == "HIGH"
    )

    critical = sum(
        1 for finding in findings
        if finding["risk_level"] == "CRITICAL"
    )

    open_count = sum(
        1 for finding in findings
        if finding["status"] == "Open"
    )

    return render_template(
        "dashboard.html",
        findings=findings,
        total=total,
        high=high,
        critical=critical,
        open_count=open_count
    )


# -------------------------------------------------
# Add Vulnerability
# -------------------------------------------------

@app.route("/add", methods=["POST"])
def add_finding():

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    asset = request.form.get("asset")
    vulnerability = request.form.get("vulnerability")

    try:
        likelihood = int(request.form.get("likelihood"))
        impact = int(request.form.get("impact"))
    except (TypeError, ValueError):
        return redirect(url_for("dashboard"))

    evidence = request.form.get("evidence")

    score, risk_level = calculate_risk(
        likelihood,
        impact
    )

    recommendation = recommendations.get(
        vulnerability,
        "Review the vulnerability and apply appropriate security controls."
    )

    finding = {
        "id": len(findings) + 1,
        "asset": asset,
        "vulnerability": vulnerability,
        "likelihood": likelihood,
        "impact": impact,
        "score": score,
        "risk_level": risk_level,
        "evidence": evidence,
        "recommendation": recommendation,
        "status": "Open"
    }

    findings.append(finding)

    return redirect(url_for("dashboard"))


# -------------------------------------------------
# Delete Finding
# -------------------------------------------------

@app.route("/delete/<int:finding_id>")
def delete_finding(finding_id):

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    global findings

    findings = [
        finding
        for finding in findings
        if finding["id"] != finding_id
    ]

    return redirect(url_for("dashboard"))


# -------------------------------------------------
# Change Finding Status
# -------------------------------------------------

@app.route("/resolve/<int:finding_id>")
def resolve_finding(finding_id):

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    for finding in findings:

        if finding["id"] == finding_id:

            if finding["status"] == "Open":
                finding["status"] = "Resolved"
            else:
                finding["status"] = "Open"

    return redirect(url_for("dashboard"))


# -------------------------------------------------
# Export CSV
# -------------------------------------------------

@app.route("/export")
def export_csv():

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Asset",
        "Vulnerability",
        "Likelihood",
        "Impact",
        "Risk Score",
        "Risk Level",
        "Evidence",
        "GRC Recommendation",
        "Status"
    ])

    for finding in findings:

        writer.writerow([
            finding["id"],
            finding["asset"],
            finding["vulnerability"],
            finding["likelihood"],
            finding["impact"],
            finding["score"],
            finding["risk_level"],
            finding["evidence"],
            finding["recommendation"],
            finding["status"]
        ])

    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="VAPT_GRC_Assessment_Report.csv"
    )


# -------------------------------------------------
# Logout
# -------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# -------------------------------------------------
# Run Application
# -------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)