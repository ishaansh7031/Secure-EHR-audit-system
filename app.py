import os
import random
import bcrypt
import json
import ast
import hashlib
from functools import wraps
from flask import (Flask, render_template, session, request, jsonify, redirect, url_for)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from datetime import datetime
from ehr_crypto import EHRCrypto
from key_manager import KeyManager
from pathlib import Path
import hmac

AUDITOR_EMAIL = os.getenv("AUDITOR_EMAIL")
AUDITOR_PASSWORD_HASH = os.getenv("AUDITOR_PASSWORD_HASH")

def constant_time_equals(a, b):
    return hmac.compare_digest(a.encode(), b.encode())
# Flask & DB Setup

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.environ["FLASK_SECRET"]

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'patient.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ─── AuditServer Initialization ───────────────────────────────────────────────

SERVER_PRIV_PATH = os.path.join(BASE_DIR, 'keys', 'server_priv.pem')
AUDITOR_PUB_PATHS = {
    "Auditor1": os.path.join(BASE_DIR, 'keys', 'auditor1_pub.pem'),
}
AUDIT_DB_PATH = os.path.join(BASE_DIR, 'audit.db')

notifier_config = {
    'name': "Audit Server",
    'rate': 5,
    'identity': {
        'name': "Audit Server",
        'ip': "127.0.0.1",
        'node_port': 0,
        'server_port': 0
    }
}

# ─── Models ────────────────────────────────────────────────────────────────────

class Patient(db.Model):
    __tablename__ = 'patients'
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password_salt = db.Column(db.String(64), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def __init__(self, firstname, lastname, email, password):
        self.id = random.randint(1, 1_000_000)
        self.firstname = firstname
        self.lastname = lastname
        self.email = email
        salt = bcrypt.gensalt()
        self.password_salt = salt.decode()
        self.password_hash = bcrypt.hashpw(password.encode(), salt).decode()

class EHR(db.Model):
    __tablename__ = 'ehrs'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)

    ciphertext = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.Text, nullable=False)
    tag = db.Column(db.Text, nullable=False)
    wrapped_key = db.Column(db.Text, nullable=False)
    ehr_hash = db.Column(db.String(128), nullable=False)  # New hash field

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    patient = db.relationship('Patient', backref=db.backref('ehrs', lazy=True))


class ZKPSubmission(db.Model):
    __tablename__ = 'zkp_submissions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    proof = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    patient = db.relationship('Patient', backref=db.backref('zkp_submissions', lazy=True))


# ─── Helpers ──────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

import requests

def log_to_audit(user_id, action_data):
    try:
        requests.post("http://127.0.0.1:6000/append-record", json={
            "user_id": str(user_id),
            "action_data": action_data
        })
    except Exception as e:
        print(f"[Audit Logging Error] {e}")


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first = request.form['firstname']
        last = request.form['lastname']
        email = request.form['email']
        pwd = request.form['password']
        confirm = request.form['confirm']
        if pwd != confirm:
            return render_template('err_pw_mismatch.html')
        if Patient.query.filter_by(email=email).first():
            return render_template('signup_failure.html'), 400

        user = Patient(first, last, email, pwd)
        db.session.add(user)
        db.session.commit()

        log_to_audit(
            user_id=user.id,
            action_data={
                "event": "LOGIN",
                "timestamp": datetime.utcnow().isoformat()
            }
        )

        session['user_id'] = user.id
        return render_template('signup_success.html', user=user)

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role')

        if role == 'auditor':
            if not AUDITOR_EMAIL or not AUDITOR_PASSWORD_HASH:
                raise RuntimeError("Auditor credentials not configured")

            if (
                constant_time_equals(email, AUDITOR_EMAIL)
                and bcrypt.checkpw(password.encode(), AUDITOR_PASSWORD_HASH.encode())
            ):
                session['auditor'] = True
                return redirect(url_for('auditor_dashboard'))

            return render_template('login_failure.html'), 401


        user = Patient.query.filter_by(email=email).first()
        if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
            return render_template('login_failure.html'), 401

        session['user_id'] = user.id
        log_to_audit(
            user_id=str(user.id),
            action_data={
                "event": "LOGIN",
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = Patient.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)


@app.route('/patients')
@login_required
def list_patients():
    log_to_audit(
        user_id=str(session['user_id']),
        action_data={
            "event": "LIST_PATIENTS",
            "timestamp": datetime.utcnow().isoformat()
        }
    )
    patients = Patient.query.order_by(Patient.email).all()
    return render_template('patients.html', patients=patients)


@app.route('/create-ehr', methods=['GET', 'POST'])
@login_required
def create_ehr():
    if request.method == 'POST':
        data = request.form['ehr_data']
        log_to_audit(
            user_id=str(session['user_id']),
            action_data={
                "event": "CREATE_EHR",
                "data": data,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        return redirect(url_for('dashboard'))
    return render_template('create_ehr.html')


@app.route('/delete-ehr', methods=['GET', 'POST'])
@login_required
def delete_ehr():
    if request.method == 'POST':
        ehr_id = request.form['ehr_id']
        ehr_record = EHR.query.filter_by(id=ehr_id, patient_id=session['user_id']).first()

        if ehr_record:
            db.session.delete(ehr_record)
            db.session.commit()

            log_to_audit(
                user_id=str(session['user_id']),
                action_data={
                    "event": "DELETE_EHR",
                    "data": ehr_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )

        return redirect(url_for('dashboard'))

    ehrs = EHR.query.filter_by(patient_id=session['user_id']).all()
    return render_template('delete_ehr.html', ehrs=ehrs)



@app.route('/change-ehr', methods=['GET', 'POST'])
@login_required
def change_ehr():
    from ehr_crypto import EHRCrypto
    from key_manager import KeyManager
    from pathlib import Path

    rsa_pub = KeyManager.load_public(Path("keys/server_pub.pem"))
    patient_id = session['user_id']

    if request.method == 'POST':
        ehr_id = request.form['ehr_id']
        new_data = request.form['ehr_change']

        ehr_record = EHR.query.filter_by(id=ehr_id, patient_id=patient_id).first()
        if not ehr_record:
            return "EHR not found or unauthorized", 404

        # Encrypt updated data
        plaintext = {
            "ehr": new_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        enc = EHRCrypto.encrypt_ehr(plaintext, rsa_pub)

        # Update the record
        ehr_record.ciphertext = enc['ciphertext']
        ehr_record.nonce = enc['nonce']
        ehr_record.tag = enc['tag']
        ehr_record.wrapped_key = enc['wrapped_key']
        ehr_record.timestamp = datetime.utcnow()

        ehr_hash_input = enc['ciphertext'] + enc['nonce'] + enc['tag'] + enc['wrapped_key']
        ehr_record.ehr_hash = hashlib.sha256(ehr_hash_input.encode()).hexdigest()

        db.session.commit()

        log_to_audit(
            user_id=str(patient_id),
            action_data={
                "event": "MODIFY_EHR",
                "data": f"Updated EHR ID {ehr_id}",
                "timestamp": plaintext["timestamp"],
                "target_patient_id": session['user_id']
            }
        )

        return redirect(url_for('dashboard'))

    # For GET: show EHRs to choose from
    ehrs = EHR.query.filter_by(patient_id=patient_id).all()
    return render_template('change_ehr.html', ehrs=ehrs)



@app.route('/query-ehr', methods=['GET', 'POST'])
@login_required
def query_ehr():
    records = []
    if request.method == 'POST':
        try:
            resp = requests.get(f"http://127.0.0.1:6000/query-user/{session['user_id']}")
            records = resp.json()
        except Exception as e:
            print(f"[Audit Query Error] {e}")
    return render_template('query_ehr.html', records=records)


@app.route('/print-ehr')
@login_required
def print_ehr():
    from ehr_crypto import EHRCrypto
    from key_manager import KeyManager
    from pathlib import Path

    rsa_priv = KeyManager.load_private(Path("keys/server_priv.pem"))

    patient_id = session['user_id']
    records = EHR.query.filter_by(patient_id=patient_id).order_by(EHR.timestamp.desc()).all()

    decrypted_records = []
    for record in records:
        try:
            decrypted = EHRCrypto.decrypt_ehr({
                "ciphertext": record.ciphertext,
                "nonce": record.nonce,
                "tag": record.tag,
                "wrapped_key": record.wrapped_key
            }, rsa_priv)
            decrypted_records.append(decrypted)
        except Exception:
            decrypted_records.append({
                "ehr": "[Decryption Failed]",
                "timestamp": str(record.timestamp)
            })

    log_to_audit(
        user_id=str(session['user_id']),
        action_data={
            "event": "PRINT_EHR",
            "timestamp": datetime.utcnow().isoformat()
        }
    )

    return render_template('print_ehr.html', records=decrypted_records)



@app.route('/copy-ehr')
@login_required
def copy_ehr():
    log_to_audit(
        user_id=str(session['user_id']),
        action_data={
            "event": "COPY_EHR",
            "timestamp": datetime.utcnow().isoformat(),
            "target_patient_id": session['user_id']
        }
    )
    return render_template('copy_ehr.html')


@app.route('/auditor-dashboard')
def auditor_dashboard():
    if not session.get('auditor'):
        return redirect(url_for('login'))

    try:
        resp = requests.get("http://127.0.0.1:6000/query-user")
        records = resp.json()
    except Exception as e:
        print(f"[Audit Query Error] {e}")
        records = []

    zkp_submissions = ZKPSubmission.query.order_by(ZKPSubmission.timestamp.desc()).all()

    #Check EHR integrity for logs that reference EHRs
    ehr_integrity = []
    for rec in records:
        user_id = rec.get('user_id')
        timestamp = rec.get('timestamp') or rec.get('action', {}).get('timestamp')
        event = rec.get('event') or rec.get('action', {}).get('event')
        status = 'N/A'

        if event in ['STORE_EHR', 'MODIFY_EHR', 'CREATE_EHR']:
            ehr = EHR.query.filter_by(patient_id=user_id).order_by(EHR.timestamp.desc()).first()
            if ehr:
                try:
                    ehr_hash_input = ehr.ciphertext + ehr.nonce + ehr.tag + ehr.wrapped_key
                    computed = hashlib.sha256(ehr_hash_input.encode()).hexdigest()
                    status = 'Valid' if computed == ehr.ehr_hash else 'Tampered'
                except:
                    status = 'Tampered'
        ehr_integrity.append(status)

    return render_template('auditor_dashboard.html', records=records, proofs=zkp_submissions, integrity=ehr_integrity)


@app.route('/api/audit/<uid>')
@login_required
def get_audit(uid):
    try:
        resp = requests.get(f"http://127.0.0.1:6000/query-user/{uid}")
        recs = resp.json()
    except Exception as e:
        print(f"[Audit Query Error] {e}")
        recs = []
    return jsonify(recs)



@app.route('/store-ehr', methods=['GET', 'POST'])
@login_required
def store_ehr():
    if request.method == 'POST':
        # Load server public key or a dedicated encryption key
        rsa_pub = KeyManager.load_public(Path("keys/server_pub.pem"))

        ehr_data = request.form['ehr_data']
        plaintext = {
            "ehr": ehr_data,
            "timestamp": datetime.utcnow().isoformat(),
            "target_patient_id": session['user_id']
        }

        enc = EHRCrypto.encrypt_ehr(plaintext, rsa_pub)


        ehr_hash_input = enc['ciphertext'] + enc['nonce'] + enc['tag'] + enc['wrapped_key']
        ehr_hash = hashlib.sha256(ehr_hash_input.encode()).hexdigest()

        new_record = EHR(
            patient_id=session['user_id'],
            ciphertext=enc['ciphertext'],
            nonce=enc['nonce'],
            tag=enc['tag'],
            wrapped_key=enc['wrapped_key'],
            ehr_hash=ehr_hash
        )
        db.session.add(new_record)
        db.session.commit()

        log_to_audit(
            user_id=str(session['user_id']),
            action_data={
                "event": "STORE_EHR",
                "timestamp": plaintext["timestamp"]
            }
        )

        return redirect(url_for('dashboard'))

    return render_template('store_ehr.html')

@app.route('/view-ehr')
@login_required
def view_ehr():
    from ehr_crypto import EHRCrypto
    from key_manager import KeyManager
    from pathlib import Path

    # Load server's private key
    rsa_priv = KeyManager.load_private(Path("keys/server_priv.pem"))

    patient_id = session['user_id']
    records = EHR.query.filter_by(patient_id=patient_id).order_by(EHR.timestamp.desc()).all()

    decrypted_records = []
    for record in records:
        try:
            ehr_hash_input = record.ciphertext + record.nonce + record.tag + record.wrapped_key
            computed_hash = hashlib.sha256(ehr_hash_input.encode()).hexdigest()

            if computed_hash != record.ehr_hash:
                decrypted_records.append({
                    "ehr": "[Tampering Detected]",
                    "timestamp": str(record.timestamp)
                })
                log_to_audit(
                    user_id=str(session['user_id']),
                    action_data={
                        "event": "TAMPERED_EHR_VIEW",
                        "timestamp": datetime.utcnow().isoformat(),
                        "target_patient_id": session['user_id']
                    }
                )
            else:
                try:
                    decrypted = EHRCrypto.decrypt_ehr({
                        "ciphertext": record.ciphertext,
                        "nonce": record.nonce,
                        "tag": record.tag,
                        "wrapped_key": record.wrapped_key
                    }, rsa_priv)
                    decrypted_records.append(decrypted)
                except Exception:
                    decrypted_records.append({
                        "ehr": "[Decryption Failed]",
                        "timestamp": str(record.timestamp)
                    })

        except Exception as e:
            decrypted_records.append({"ehr": "[Decryption Failed]", "timestamp": str(record.timestamp)})

    return render_template('view_ehr.html', records=decrypted_records)

@app.route('/prove-access', methods=['GET'])
@login_required
def prove_access():
    from zkp.prover import fiat_shamir_prove
    p = 208351617316091241234326746312124448251235562226470491514186331217050270460481
    g = 2
    secret = session['user_id']  # Proving they are the user

    proof = fiat_shamir_prove(secret, p, g)
    return render_template('prove_access.html', proof=proof)


@app.route('/submit-proof', methods=['POST'])
@login_required
def submit_proof():
    from zkp.prover import fiat_shamir_prove 
    proof_json = request.form.get('proof')

    if not proof_json:
        return "Missing proof data", 400

    try:
        json.loads(proof_json)
    except json.JSONDecodeError:
        return "Invalid JSON format", 400

    new_submission = ZKPSubmission(
        user_id=session['user_id'],
        proof=proof_json
    )
    db.session.add(new_submission)
    db.session.commit()

    return render_template('proof_submitted.html')


@app.route('/verify-access', methods=['POST'])
def verify_access():
    from zkp.verifier import fiat_shamir_verify

    if not session.get('auditor'):
        return "Unauthorized: Only auditors can verify proofs.", 403

    try:
        proof = json.loads(request.form['proof'])
        verified = fiat_shamir_verify(proof)
    except Exception as e:
        return f"Invalid proof format: {e}", 400

    return render_template('verify_access.html', result=verified)

@app.route('/delete-proof/<int:proof_id>', methods=['POST'])
def delete_proof(proof_id):
    if not session.get('auditor'):
        return "Unauthorized", 403

    proof = ZKPSubmission.query.get(proof_id)
    if not proof:
        return "Proof not found", 404

    db.session.delete(proof)
    db.session.commit()
    return redirect(url_for('auditor_dashboard'))

@app.route('/audit-query', methods=['GET', 'POST'])
def audit_query():
    if not session.get('auditor'):
        return redirect(url_for('login'))

    users = Patient.query.order_by(Patient.id).all()
    results = []

    if request.method == 'POST':
        user_id = request.form['user_id']
        if user_id:
            try:
                resp = requests.get(f"http://127.0.0.1:6000/query-user/{user_id}")
                results = resp.json()
            except Exception as e:
                print(f"[Audit Query Error] {e}")

    return render_template('audit_query.html', users=users, results=results)


@app.route('/audit-create', methods=['GET', 'POST'])
def audit_create():
    if not session.get('auditor'):
        return redirect(url_for('login'))

    users = Patient.query.order_by(Patient.id).all()
    success = None

    if request.method == 'POST':
        user_id = request.form['user_id']
        event = request.form['event']
        data = request.form['data']
        timestamp = request.form['timestamp']

        action_data = {
            "event": event,
            "data": data,
            "timestamp": timestamp if timestamp else datetime.utcnow().isoformat()
        }

        try:
            response = requests.post("http://127.0.0.1:6000/append-record", json={
                "user_id": user_id,
                "action_data": action_data
            })
            if response.status_code == 200:
                success = True
        except Exception as e:
            print(f"[Audit Log Creation Error] {e}")
            success = False

    return render_template('audit_create.html', users=users, success=success)


@app.route('/tamper-record/<int:seq>', methods=['GET'])
def tamper_record(seq):
    if not session.get('auditor'):
        return "Unauthorized: Only auditors can simulate tampering.", 403

    from storage import AuditStore
    store = AuditStore(Path("audit.db"))

    try:
        all_records = store.fetch_all()
        if 0 < seq <= len(all_records):
            record = all_records[seq - 1]
            record['cipher'] = "00" * 16  # Simulate tampering

            store.overwrite(seq - 1, record)

            log_to_audit(
                user_id="AUDITOR",
                action_data={
                    "event": "TAMPER_SIMULATED",
                    "data": f"Record #{seq} was modified",
                    "timestamp": datetime.utcnow().isoformat()
                }
            )

            return f"Tampered with record #{seq}"
        else:
            return "Invalid sequence number", 400
    except Exception as e:
        return f"Tampering failed: {e}", 500



# ─── App Runner ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
