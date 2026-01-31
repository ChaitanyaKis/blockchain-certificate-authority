import os
import uuid
from io import BytesIO

from flask import Flask, request, render_template, redirect, url_for, send_file
from flask_cors import CORS
from dotenv import load_dotenv
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import qrcode

from database import db, Issuer, Certificate
from crypto_utils import sha256_hash, encrypt, decrypt, get_cipher
from blockchain import issue_to_blockchain, verify_on_blockchain

# ---------------- LOAD SECRETS ----------------
load_dotenv()
MASTER_KEY = os.getenv("MASTER_KEY").encode()
ISSUER_SECRET = os.getenv("ISSUER_SECRET").encode()

# ---------------- FLASK SETUP ----------------
app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
)
CORS(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///secure_certchain.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
cipher = get_cipher(MASTER_KEY)

# ---------------- ISSUER INIT ----------------
def ensure_issuer_exists():
    issuer = Issuer.query.first()
    if not issuer:
        issuer = Issuer(
            encrypted_name=encrypt("Hackathon Authority", cipher),
            secret_hash=sha256_hash(ISSUER_SECRET.decode())
        )
        db.session.add(issuer)
        db.session.commit()

with app.app_context():
    db.create_all()
    ensure_issuer_exists()

# ---------------- ROUTES ----------------
@app.route("/")
def home():
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

# ---------------- ISSUE ----------------
@app.route("/issue", methods=["GET", "POST"])
def issue():
    message = None
    issued_cert_id = None

    if request.method == "POST":
        holder_name = request.form["holder_name"].strip()
        description = request.form["cert_data"].strip()
        issuer_key = request.form["issuer_key"].strip()

        issuer = Issuer.query.first()

        if sha256_hash(issuer_key) != issuer.secret_hash:
            message = "❌ Unauthorized Issuer"
        else:
            cert_id = f"CERT-{uuid.uuid4().hex[:6].upper()}"
            serial_number = f"SCA-{uuid.uuid4().hex[:8].upper()}"

            hash_input = f"{cert_id}|{holder_name}|{description}"
            cert_hash = sha256_hash(hash_input)

            issue_to_blockchain(cert_id, cert_hash)

            cert = Certificate(
                cert_id=cert_id,
                serial_number=serial_number,
                cert_hash=cert_hash,
                holder_name=holder_name,
                description=description
            )

            db.session.add(cert)
            db.session.commit()

            issued_cert_id = cert_id
            message = "✅ Certificate Issued Successfully"

    return render_template(
        "issue.html",
        message=message,
        issued_cert_id=issued_cert_id
    )

# ---------------- VERIFY ----------------
@app.route("/verify", methods=["GET", "POST"])
def verify():
    result = None
    cert_id = None

    if request.method == "POST":
        cert_id = request.form["cert_id"].strip()
        holder_name = request.form["holder_name"].strip()
        description = request.form["cert_data"].strip()

        cert = Certificate.query.filter_by(cert_id=cert_id).first()

        if not cert:
            result = "❌ Certificate Not Found"
        elif cert.status == "REVOKED":
            result = "❌ Certificate Revoked"
        else:
            hash_input = f"{cert_id}|{holder_name}|{description}"
            cert_hash = sha256_hash(hash_input)

            if verify_on_blockchain(cert_id, cert_hash):
                result = "AUTHENTIC"
            else:
                result = "TAMPERED"

    return render_template(
        "verify.html",
        result=result,
        cert_id=cert_id
    )

# ---------------- REVOKE ----------------
@app.route("/revoke", methods=["GET", "POST"])
def revoke():
    message = None

    if request.method == "POST":
        cert_id = request.form["cert_id"].strip()
        issuer_key = request.form["issuer_key"].strip()

        issuer = Issuer.query.first()
        cert = Certificate.query.filter_by(cert_id=cert_id).first()

        if sha256_hash(issuer_key) != issuer.secret_hash:
            message = "❌ Unauthorized Issuer"
        elif not cert:
            message = "❌ Certificate Not Found"
        else:
            cert.status = "REVOKED"
            db.session.commit()
            message = "⚠️ Certificate Revoked"

    return render_template("revoke.html", message=message)

# ---------------- CERTIFICATE VIEW ----------------
@app.route("/certificate/<cert_id>")
def certificate_view(cert_id):
    cert = Certificate.query.filter_by(cert_id=cert_id).first()
    issuer = Issuer.query.first()

    if not cert:
        return "Certificate Not Found"

    return render_template(
        "certificate.html",
        cert=cert,
        issuer=decrypt(issuer.encrypted_name, cipher)
    )

# ---------------- VIEW CERTIFICATE REDIRECT ----------------
@app.route("/view", methods=["GET", "POST"])
def view_certificate():
    if request.method == "POST":
        cert_id = request.form["cert_id"].strip()
        return redirect(url_for("certificate_view", cert_id=cert_id))

    return render_template("view_certificate.html")



# ---------------- PUBLIC VERIFY ----------------
@app.route("/public_verify/<cert_id>")
def public_verify(cert_id):
    cert = Certificate.query.filter_by(cert_id=cert_id).first()
    return render_template("public_verify.html", cert=cert)

# ---------------- QR ----------------
@app.route("/qr/<cert_id>")
def qr_code(cert_id):
    url = request.host_url + f"public_verify/{cert_id}"
    img = qrcode.make(url)
    buf = BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

# ---------------- PDF ----------------
@app.route("/download/<cert_id>")
def download_certificate(cert_id):
    cert = Certificate.query.filter_by(cert_id=cert_id).first()
    issuer = Issuer.query.first()

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)

    pdf.setFont("Helvetica-Bold", 22)
    pdf.drawCentredString(300, 800, "Certificate of Authenticity")

    pdf.setFont("Helvetica", 14)
    pdf.drawString(80, 750, f"Serial Number: {cert.serial_number}")
    pdf.drawString(80, 720, f"Certificate ID: {cert.cert_id}")
    pdf.drawString(80, 690, f"Holder Name: {cert.holder_name}")
    pdf.drawString(80, 660, f"Issuer: {decrypt(issuer.encrypted_name, cipher)}")
    pdf.drawString(80, 630, f"Issued At: {cert.issued_at}")
    pdf.drawString(80, 600, f"Status: {cert.status}")

    pdf.showPage()
    pdf.save()

    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name=f"{cert.cert_id}.pdf",
                     mimetype="application/pdf")

if __name__ == "__main__":
    app.run(port=8080, debug=False)

