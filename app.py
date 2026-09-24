from flask import Flask, jsonify, request, session, redirect, url_for, render_template
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = "event-management-secret-key"
CORS(app)

DATABASE = "events.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'STUDENT'
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            date TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            capacity INTEGER NOT NULL,
            created_by INTEGER,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            event_id INTEGER NOT NULL,
            registered_at TEXT NOT NULL,
            UNIQUE(student_id, event_id),
            FOREIGN KEY (student_id) REFERENCES users(id),
            FOREIGN KEY (event_id) REFERENCES events(id)
        )
    """)

    conn.commit()

    # Create demo admin
    admin = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        ("admin@example.com",)
    ).fetchone()

    if not admin:
        conn.execute("""
            INSERT INTO users (name, email, password, role)
            VALUES (?, ?, ?, ?)
        """, (
            "Admin",
            "admin@example.com",
            generate_password_hash("admin123"),
            "ADMIN"
        ))

    # Create demo student
    student = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        ("student@example.com",)
    ).fetchone()

    if not student:
        conn.execute("""
            INSERT INTO users (name, email, password, role)
            VALUES (?, ?, ?, ?)
        """, (
            "Demo Student",
            "student@example.com",
            generate_password_hash("student123"),
            "STUDENT"
        ))

    conn.commit()
    conn.close()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({
                "success": False,
                "message": "Authentication required"
            }), 401

        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({
                "success": False,
                "message": "Authentication required"
            }), 401

        if session.get("role") != "ADMIN":
            return jsonify({
                "success": False,
                "message": "Admin access required"
            }), 403

        return f(*args, **kwargs)

    return decorated_function


# =========================
# AUTHENTICATION
# =========================

@app.post("/api/register")
def register():
    data = request.get_json()

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not name or not email or not password:
        return jsonify({
            "success": False,
            "message": "Name, email and password are required"
        }), 400

    conn = get_db()

    try:
        cursor = conn.execute("""
            INSERT INTO users (name, email, password, role)
            VALUES (?, ?, ?, ?)
        """, (
            name,
            email,
            generate_password_hash(password),
            "STUDENT"
        ))

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Registration successful",
            "user_id": cursor.lastrowid
        }), 201

    except sqlite3.IntegrityError:
        return jsonify({
            "success": False,
            "message": "Email already registered"
        }), 409

    finally:
        conn.close()


@app.post("/api/login")
def login():
    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    conn.close()

    if not user or not check_password_hash(user["password"], password):
        return jsonify({
            "success": False,
            "message": "Invalid email or password"
        }), 401

    session["user_id"] = user["id"]
    session["role"] = user["role"]
    session["name"] = user["name"]

    return jsonify({
        "success": True,
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    })


@app.post("/api/logout")
def logout():
    session.clear()

    return jsonify({
        "success": True,
        "message": "Logged out"
    })


@app.get("/api/me")
@login_required
def current_user():
    return jsonify({
        "success": True,
        "user": {
            "id": session["user_id"],
            "name": session["name"],
            "role": session["role"]
        }
    })


# =========================
# EVENTS
# =========================

@app.get("/api/events")
def get_events():
    conn = get_db()

    events = conn.execute("""
        SELECT
            e.*,
            COUNT(r.id) AS registered
        FROM events e
        LEFT JOIN registrations r
            ON e.id = r.event_id
        GROUP BY e.id
        ORDER BY e.date, e.start_time
    """).fetchall()

    conn.close()

    result = []

    for event in events:
        result.append({
            "id": event["id"],
            "name": event["name"],
            "date": event["date"],
            "start_time": event["start_time"],
            "end_time": event["end_time"],
            "capacity": event["capacity"],
            "registered": event["registered"],
            "available": event["capacity"] - event["registered"]
        })

    return jsonify({
        "success": True,
        "events": result
    })


@app.post("/api/events")
@admin_required
def create_event():
    data = request.get_json()

    name = data.get("name")
    date = data.get("date")
    start_time = data.get("start_time")
    end_time = data.get("end_time")
    capacity = data.get("capacity")

    if not all([name, date, start_time, end_time, capacity]):
        return jsonify({
            "success": False,
            "message": "All event fields are required"
        }), 400

    if end_time <= start_time:
        return jsonify({
            "success": False,
            "message": "End time must be later than start time"
        }), 400

    try:
        capacity = int(capacity)
    except ValueError:
        return jsonify({
            "success": False,
            "message": "Capacity must be a number"
        }), 400

    if capacity <= 0:
        return jsonify({
            "success": False,
            "message": "Capacity must be greater than zero"
        }), 400

    conn = get_db()

    cursor = conn.execute("""
        INSERT INTO events
        (name, date, start_time, end_time, capacity, created_by)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        name,
        date,
        start_time,
        end_time,
        capacity,
        session["user_id"]
    ))

    conn.commit()

    event_id = cursor.lastrowid

    conn.close()

    return jsonify({
        "success": True,
        "message": "Event created successfully",
        "event_id": event_id
    }), 201


# =========================
# REGISTRATION
# =========================

@app.post("/api/events/<int:event_id>/register")
@login_required
def register_event(event_id):
    student_id = session["user_id"]

    if session["role"] != "STUDENT":
        return jsonify({
            "success": False,
            "message": "Only students can register for events"
        }), 403

    conn = get_db()

    try:
        # Start transaction
        conn.execute("BEGIN IMMEDIATE")

        event = conn.execute("""
            SELECT *
            FROM events
            WHERE id = ?
        """, (event_id,)).fetchone()

        if not event:
            conn.rollback()

            return jsonify({
                "success": False,
                "code": "EVENT_NOT_FOUND",
                "message": "Event not found"
            }), 404

        # Duplicate registration check
        existing = conn.execute("""
            SELECT id
            FROM registrations
            WHERE student_id = ?
            AND event_id = ?
        """, (student_id, event_id)).fetchone()

        if existing:
            conn.rollback()

            return jsonify({
                "success": False,
                "code": "ALREADY_REGISTERED",
                "message": "You are already registered for this event"
            }), 409

        # Schedule conflict check
        conflicts = conn.execute("""
            SELECT
                e.name,
                e.start_time,
                e.end_time
            FROM registrations r
            JOIN events e
                ON r.event_id = e.id
            WHERE r.student_id = ?
            AND e.date = ?
            AND e.start_time < ?
            AND ? < e.end_time
        """, (
            student_id,
            event["date"],
            event["end_time"],
            event["start_time"]
        )).fetchall()

        if conflicts:
            conflict = conflicts[0]

            conn.rollback()

            return jsonify({
                "success": False,
                "code": "SCHEDULE_CONFLICT",
                "message": (
                    f"Schedule conflict with '{conflict['name']}' "
                    f"({conflict['start_time']} - {conflict['end_time']})"
                )
            }), 409

        # Capacity check
        registered_count = conn.execute("""
            SELECT COUNT(*) AS count
            FROM registrations
            WHERE event_id = ?
        """, (event_id,)).fetchone()["count"]

        if registered_count >= event["capacity"]:
            conn.rollback()

            return jsonify({
                "success": False,
                "code": "EVENT_FULL",
                "message": "This event is already full"
            }), 409

        # Create registration
        conn.execute("""
            INSERT INTO registrations
            (student_id, event_id, registered_at)
            VALUES (?, ?, ?)
        """, (
            student_id,
            event_id,
            datetime.now().isoformat()
        ))

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Successfully registered for event"
        })

    except sqlite3.IntegrityError:
        conn.rollback()

        return jsonify({
            "success": False,
            "message": "Registration could not be completed"
        }), 409

    finally:
        conn.close()


@app.get("/api/my-events")
@login_required
def my_events():
    conn = get_db()

    events = conn.execute("""
        SELECT
            e.*,
            r.registered_at
        FROM registrations r
        JOIN events e
            ON r.event_id = e.id
        WHERE r.student_id = ?
        ORDER BY e.date, e.start_time
    """, (session["user_id"],)).fetchall()

    conn.close()

    return jsonify({
        "success": True,
        "events": [dict(event) for event in events]
    })


# =========================
# FRONTEND
# =========================

@app.get("/")
def home():
    return render_template("events.html")


@app.get("/login")
def login_page():
    return render_template("login.html")


@app.get("/register")
def register_page():
    return render_template("register.html")


@app.get("/admin")
def admin_page():
    return render_template("admin.html")


if __name__ == "__main__":
    init_db()

    app.run(
        debug=True,
        port=5000
    )