from flask import Flask, render_template, request, redirect, session, url_for, flash, g
from datetime import datetime, timedelta
import os
import uuid
from functools import wraps
import boto3
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------------------
# Load .env
# ---------------------------------------
if not load_dotenv():
    print("Warning: .env file not found. Using defaults.")

# ---------------------------------------
# Flask init
# ---------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# ---------------------------------------
# DynamoDB & SNS
# ---------------------------------------
AWS_REGION = os.environ.get('AWS_REGION_NAME', 'ap-south-1')
USERS_TABLE = os.environ.get('USERS_TABLE_NAME', 'MedTrackUsers')
PATIENTS_TABLE = os.environ.get('PATIENTS_TABLE_NAME', 'MedTrackPatients')
DOCTORS_TABLE = os.environ.get('DOCTORS_TABLE_NAME', 'MedTrackDoctors')
APPOINTMENTS_TABLE = os.environ.get('APPOINTMENTS_TABLE_NAME', 'MedTrackAppointments')
PRESCRIPTIONS_TABLE = os.environ.get('PRESCRIPTIONS_TABLE_NAME', 'MedTrackPrescriptions')

try:
    if os.environ.get("AWS_ACCESS_KEY_ID"):
        dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
        sns = boto3.client("sns", region_name=AWS_REGION)
        SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
    else:
        dynamodb = None
        sns = None
        SNS_TOPIC_ARN = None
        print("AWS credentials not found. Using local fallback.")
except Exception as e:
    print(f"DynamoDB/SNS init failed: {e}")
    dynamodb = None
    sns = None
    SNS_TOPIC_ARN = None

# SNS
def publish_to_sns(message, subject="MedTrack Notification"):
    if sns and SNS_TOPIC_ARN:
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Message=message,
                Subject=subject
            )
        except Exception as e:
            print(f"SNS error: {e}")
    else:
        print("SNS not configured, skipping publish.")

# ---------------------------------------
# Local fallback DB
# ---------------------------------------
local_db = {
    "users": {},
    "patients": {},
    "doctors": {},
    "appointments": {},
    "prescriptions": {}
}

# ---------------------------------------
# Helpers
# ---------------------------------------
def get_table(name):
    if dynamodb:
        return dynamodb.Table(name)
    return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_email' not in session:
            flash("Login required", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------
# Load logged-in user
# ---------------------------------------
@app.before_request
def load_logged_in_user():
    email = session.get('user_email')
    g.user = None
    if email:
        if dynamodb:
            try:
                table = get_table(USERS_TABLE)
                resp = table.get_item(Key={'email': email})
                if 'Item' in resp:
                    g.user = resp['Item']
            except Exception as e:
                print(f"Error loading user: {e}")
        else:
            g.user = local_db['users'].get(email)

# ---------------------------------------
# Routes
# ---------------------------------------

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('username')
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        role = request.form.get('role', 'patient')

        if not name or not email or not password:
            flash("All fields required", "danger")
            return redirect(url_for('signup'))
        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for('signup'))

        hashed = generate_password_hash(password)
        user_data = {
            "email": email,
            "name": name,
            "password": hashed,
            "role": role,
            "created_at": datetime.now().isoformat()
        }
        if dynamodb:
            try:
                get_table(USERS_TABLE).put_item(Item=user_data)
                publish_to_sns(
                    f"New user registered: {name} ({role})",
                    subject="MedTrack Signup"
                )
            except Exception as e:
                print(f"Error saving user: {e}")
        else:
            local_db['users'][email] = user_data

        session.clear()
        session['user_email'] = email
        flash("Signup successful", "success")
        return redirect(url_for('login'))
    return render_template("signup.html")

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        print(f"Login attempt for: {email}")
        user = None
        if dynamodb:
            try:
                resp = get_table(USERS_TABLE).get_item(Key={'email': email})
                user = resp.get('Item')
            except Exception as e:
                print(f"Error fetching user: {e}")
        else:
            user = local_db['users'].get(email)

        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user_email'] = email
            flash("Login successful", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials", "danger")
    return render_template("login.html")

#@app.route('/dashboard')
#@login_required
#def dashboard():
 #   return render_template("dashboard.html", user=g.user)

@app.route('/dashboard')
@login_required
def dashboard():
    patient_count = 0
    if g.user['role'] == 'doctor':
        if dynamodb:
            try:
                scan = get_table(PATIENTS_TABLE).scan()
                patient_count = len(scan.get('Items', []))
            except Exception as e:
                print(f"Error counting patients: {e}")
        else:
            patient_count = len(local_db['patients'])
    return render_template("dashboard.html", user=g.user, patient_count=patient_count)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))

# ---------------------------------------
# PATIENT
# ---------------------------------------
@app.route('/patient', methods=['GET','POST'])
@login_required
def patient():
    if g.user and g.user.get('role') != 'patient':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        pdata = {
            "id": str(uuid.uuid4()),  # Unique ID for every entry
            "user_email": g.user['email'],
            "name": request.form.get('name'),
            "age": request.form.get('age'),
            "gender": request.form.get('gender'),
            "contact": request.form.get('contact'),
            "address": request.form.get('address'),
            "blood_group": request.form.get('bloodGroup'),
            "medical_history": request.form.get('medicalHistory'),
            "updated_at": datetime.now().isoformat()
        }
        if dynamodb:
            try:
                get_table(PATIENTS_TABLE).put_item(Item=pdata)
                flash("Patient record saved", "success")
            except Exception as e:
                print(f"Error saving patient: {e}")
        else:
            local_db['patients'][pdata['id']] = pdata
            flash("Patient record saved locally", "success")
        return redirect(url_for('psubmitted'))

    return render_template("patient.html")
# ---------------------------------------
# DOCTOR
# ---------------------------------------
@app.route('/doctor_profile', methods=['GET', 'POST'])
@login_required
def doctor_profile():
    #if g.user and g.user.get('role') != 'doctor':
       # flash("Access denied.", "danger")
       # return redirect(url_for('dashboard'))  # Not login

    if request.method == 'POST':
        ddata = {
            "email": g.user['email'],
            "name": g.user['name'],
            "age": request.form.get('docAge'),
            "gender": request.form.get('docGender'),
            "specialist": request.form.get('specialization'),
            "experience": request.form.get('experience'),
            "contact": request.form.get('docContact'),
            "address": request.form.get('docAddress'),
            "availability": request.form.get('availability'),
            "qualifications": request.form.get('qualifications', 'MBBS'),
            "updated_at": datetime.now().isoformat()
        }
        if dynamodb:
            try:
                get_table(DOCTORS_TABLE).put_item(Item=ddata)
                flash("Doctor details saved", "success")
            except Exception as e:
                print(f"Error saving doctor: {e}")
        else:
            local_db['doctors'][g.user['email']] = ddata
            flash("Doctor details saved locally", "success")
        return redirect(url_for('doctor_submitted'))  # Or dashboard if you prefer

    details = None
    if dynamodb:
        try:
            resp = get_table(DOCTORS_TABLE).get_item(Key={'email': g.user['email']})
            details = resp.get('Item')
        except Exception as e:
            print(f"Error loading doctor: {e}")
    else:
        details = local_db['doctors'].get(g.user['email'])
    return render_template("doctor_profile.html", details=details)


# ---------------------------------------
# PRESCRIPTIONS
# ---------------------------------------
@app.route('/prescriptions')
@login_required
def prescriptions():
    data = []
    if dynamodb:
        try:
            scan = get_table(PRESCRIPTIONS_TABLE).scan()
            data = [p for p in scan['Items'] if p['email'] == g.user['email']]
        except Exception as e:
            print(f"Error loading prescriptions: {e}")
    else:
        data = [p for p in local_db['prescriptions'].values() if p['email'] == g.user['email']]
    return render_template("prescriptions.html", prescriptions=data)

@app.route('/add_medicine', methods=['GET', 'POST'])
@login_required
def add_medicine():
    if request.method == 'POST':
        mdata = {
            "id": str(uuid.uuid4()),
            "email": g.user['email'],  # User's own email
            "medicine": request.form.get('name'),
            "dosage": request.form.get('dosage'),
            "frequency": request.form.get('frequency'),
            "doctor": request.form.get('doctor'),  # Or you can label as "Self"
            "date": datetime.now().isoformat()
        }
        if dynamodb:
            try:
                get_table(PRESCRIPTIONS_TABLE).put_item(Item=mdata)
                flash("Prescription saved", "success")
            except Exception as e:
                print(f"Error saving prescription: {e}")
        else:
            local_db['prescriptions'][mdata['id']] = mdata
            flash("Prescription saved locally", "success")
        return redirect(url_for('dashboard'))

    return render_template("add_medicine.html")


# ---------------------------------------
# STATIC
# ---------------------------------------
@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/contact')
def contact():
    return render_template("contact.html")

@app.route('/services')
def services():
    return render_template("services.html")

@app.route('/psubmitted')
def psubmitted():
    return render_template("psubmitted.html")

@app.route('/apsucess')
def apsucess():
    return render_template("apsucess.html")

@app.route('/doctor_submitted')
def doctor_submitted():
    return render_template("doctor_submitted.html")

@app.route('/health_tips')
def health_tips():
    return render_template("health_tips.html")


@app.route('/basci_medicine')
def basic_medicine():
    return render_template("basic_medicine.html")

@app.route('/registered_patients')
@login_required
def registered_patients():
    #if g.user['role'] != 'doctor':
     #   flash("Only doctors can view registered patients.", "danger")
      #  return redirect(url_for('dashboard'))

    patients = []
    if dynamodb:
        try:
            #table = get_table(PATIENTS_TABLE)
            scan = get_table(PATIENTS_TABLE).scan()
            patients = scan.get('Items', [])
        except Exception as e:
            print(f"Error fetching patients: {e}")
    else:
        patients = list(local_db['patients'].values())

    return render_template("registered_patients.html", patients=patients)


@app.route('/specialist')
def specialist():
    doctors = []
    if dynamodb:
        try:
            scan = get_table(DOCTORS_TABLE).scan()
            doctors = scan.get('Items', [])
        except Exception as e:
            print(f"Error loading doctors: {e}")
    else:
        doctors = list(local_db['doctors'].values())
    return render_template("specialist.html", doctors=doctors)

@app.route('/book_appointment', methods=['GET', 'POST'])
@login_required
def book_appointment():
    if g.user and g.user.get('role') != 'patient':
        flash("Only patients can book appointments.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        data = {
            "id": str(uuid.uuid4()),
            "email": g.user['email'],
            "name": g.user['name'],
            "department": request.form.get('department'),
            "doctor": request.form.get('doctor'),
            "date": request.form.get('date'),
            "time": request.form.get('time'),
            "notes": request.form.get('notes'),
            "created_at": datetime.now().isoformat()
        }
        if dynamodb:
            try:
                get_table(APPOINTMENTS_TABLE).put_item(Item=data)
                flash("Appointment booked!", "success")
            except Exception as e:
                print(f"Error saving appointment: {e}")
        else:
            local_db['appointments'][data['id']] = data
            flash("Appointment booked locally!", "success")
        return redirect(url_for('apsucess'))

    return render_template("book_appointment.html")

# ---------------------------------------
# MAIN
# ---------------------------------------
if __name__ == "__main__":
    app.run(debug=True)