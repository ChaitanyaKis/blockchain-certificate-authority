from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid

db = SQLAlchemy()

def uid():
    return str(uuid.uuid4())

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Issuer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    encrypted_name = db.Column(db.Text, nullable=False)
    secret_hash = db.Column(db.String(256), nullable=False)


class AuditLog(db.Model):
    id = db.Column(db.String, primary_key=True, default=uid)
    encrypted_event = db.Column(db.LargeBinary, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Certificate(db.Model):
    id = db.Column(db.String, primary_key=True, default=uid)

    cert_id = db.Column(db.String(100), unique=True, nullable=False)
    serial_number = db.Column(db.String(20), unique=True, nullable=False)  # ✅ NEW

    cert_hash = db.Column(db.String(256), nullable=False)
    holder_name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)

    issued_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="ACTIVE")

