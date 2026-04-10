from apis.auth_api import check_fields, check_signed
import bcrypt, os, random, re, sqlite3
from flask import Blueprint, current_app, jsonify, redirect, render_template, request, send_file
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

db = sqlite3.connect("data.db")
cursor = db.cursor()
cursor.row_factory = sqlite3.Row
cursor.execute("SELECT * FROM users WHERE username=?", (os.getenv("ADMIN_USERNAME"),))
row = cursor.fetchone()
if not row:
	while True:
		user_token = random.randint(1000000000, 9999999999)
		cursor.execute("SELECT * FROM users WHERE token=?", (user_token,))
		row = cursor.fetchone()
		if not row:
			break
	admin_password = bcrypt.hashpw(os.getenv("ADMIN_PASSWORD").encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
	cursor.execute("INSERT INTO users (username, password, token, admin) VALUES(?, ?, ?, ?)",
		(os.getenv("ADMIN_USERNAME").strip().lower(), admin_password, user_token, 1))
	db.commit()
db.close()

admin = Blueprint("admin", __name__)

@admin.route("/admin", methods=["GET"])
def admin_page():
	row = check_signed(request.cookies)
	if not row:
		return redirect("/auth")
	if not row.get("admin"):
		return redirect("/")
	return render_template("admin.html")

@admin.route("/user/create", methods=["POST"])
def user_create():
	row = check_signed(request.cookies)
	if not row:
		return redirect("/auth")
	if not row.get("admin"):
		return redirect("/")
	required_fields = ["username", "password"]
	error = check_fields(request.form, required_fields)
	if error:
		return error
	username = request.form.get("username").lower().strip()
	if re.search(r"[^a-z0-9_]", username):
		return jsonify({
			"error": "Only alphanums and _ allowed",
			"field": "username"
		})
	password = request.form.get("password")
	if not re.match(r"(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^a-zA-Z0-9]).{16,}", password):
		return jsonify({
			"error": "The password is weak",
			"field": "password"
		})
	db = sqlite3.connect("data.db")
	cursor = db.cursor()
	cursor.row_factory = sqlite3.Row
	cursor.execute("SELECT * FROM users WHERE username=?", (username,))
	row = cursor.fetchone()
	if row:
		db.close()
		return jsonify({
			"error": "The username is already taken",
			"field": "username"
		}), 400
	while True:
		user_token = random.randint(1000000000, 9999999999)
		cursor.execute("SELECT * FROM users WHERE token=?", (user_token,))
		row = cursor.fetchone()
		if not row:
			break
	password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
	cursor.execute("INSERT INTO users (username, password, token) VALUES(?, ?, ?)",
		(username, password, user_token))
	cursor.execute("SELECT id, username, status FROM users WHERE username=?", (username,))
	row = cursor.fetchone()
	row = dict(row)
	cursor.execute(f"""CREATE TABLE IF NOT EXISTS fys_{row.get("id")} (
		id INTEGER PRIMARY KEY UNIQUE NOT NULL,
		name TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT "open"
	)""")
	db.commit()
	db.close()
	return jsonify({
		"success": 1,
		"row": row
	}), 200

@admin.route("/user/read", methods=["GET"]) 
def user_read():
	row = check_signed(request.cookies)
	if not row:
		return redirect("/auth")
	if not row.get("admin"):
		return redirect("/")
	db = sqlite3.connect("data.db")
	cursor = db.cursor()
	cursor.row_factory = sqlite3.Row
	cursor.execute(f"SELECT id, username, status FROM users WHERE admin!=?", (1,))
	rows = cursor.fetchall()
	rows = [dict(row) for row in rows]
	db.close()
	user_q = request.args.get("user_q")
	if rows and user_q:
		vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4))
		tfidf_matrix = vectorizer.fit_transform([row["username"].lower() for row in rows])
		query_vec = vectorizer.transform([user_q.strip().lower()])
		sim_scores = cosine_similarity(query_vec, tfidf_matrix).flatten()
		rows = [rows[i] for i in sim_scores.argsort()[::-1] if sim_scores[i] >= 0.3]
	return jsonify(rows), 200

@admin.route("/user/update", methods=["PATCH"])
def user_update():
	row = check_signed(request.cookies)
	if not row:
		return redirect("/auth")
	if not row.get("admin"):
		return redirect("/")
	db = sqlite3.connect("data.db")
	cursor = db.cursor()
	cursor.row_factory = sqlite3.Row
	error = check_fields(request.form, ["id", "purpose"])
	if error:
		db.close()
		return jsonify(error), 400
	purpose = request.form.get("purpose").strip()
	id = request.form.get("id").strip()
	if purpose == "update_status":
		cursor.execute(f"SELECT * FROM users WHERE id=? AND admin!=?", (id, 1))
		row = cursor.fetchone()
		if not row:
			db.close()
			return jsonify({"error": "Invalid id"}), 400
		row = dict(row)
		status = row.get("status")
		cursor.execute(f"UPDATE users SET status=? WHERE id=?", ("locked" if status == "unlocked" else "unlocked", row.get("id")))
		db.commit()
		db.close()
		return jsonify({"success": 1, "status": "locked" if status == "unlocked" else "unlocked"}), 200
	else:
		return jsonify({"error": "Invalid purpose"}), 400

@admin.route("/user/delete", methods=["DELETE"])
def user_delete():
	row = check_signed(request.cookies)
	if not row:
		return redirect("/auth")
	if not row.get("admin"):
		return redirect("/")
	db = sqlite3.connect("data.db")
	cursor = db.cursor()
	cursor.row_factory = sqlite3.Row
	error = check_fields(request.form, ["id"])
	if error:
		db.close()
		return jsonify(error), 400
	id = request.form.get("id").strip()
	cursor.execute(f"SELECT * FROM users WHERE id=? AND admin!=?", (id, 1))
	row = cursor.fetchone()
	if not row:
		db.close()
		return jsonify({"error": "Invalid id"}), 400
	row = dict(row)
	cursor.execute(f"DELETE FROM users WHERE id=?", (row.get("id"),))
	cursor.execute(f"SELECT id FROM fys_{row.get("id")}")
	ids = cursor.fetchall()
	ids = [dict(i) for i in ids]
	cursor.execute(f"""DROP TABLE "fys_{row.get("id")}" """)
	for i in ids:
		cursor.execute(f"""DROP TABLE IF EXISTS "journal_{row.get("id")}_{i.get("id")}" """)
		cursor.execute(f"""DROP TABLE IF EXISTS "bs_{row.get("id")}_{i.get("id")}" """)
	db.commit()
	db.close()
	return jsonify({"success": 1}), 200

@admin.route("/export", methods=["GET"])
def export_db():
	row = check_signed(request.cookies)
	if not row:
		return redirect("/auth")
	if not row.get("admin"):
		return redirect("/")
	return send_file(os.path.join(current_app.root_path, "data.db"), as_attachment=True)

@admin.route("/import", methods=["POST"])
def import_db():
	row = check_signed(request.cookies)
	if not row:
		return redirect("/auth")
	if not row.get("admin"):
		return redirect("/")
	data = request.files["data"]
	if not data:
		return jsonify({"error": "Field data is empty"}), 400
	db = sqlite3.connect("data.db")
	cursor = db.cursor()
	cursor.row_factory = sqlite3.Row
	cursor.execute("SELECT * FROM users WHERE username='admin'")
	admin_data = dict(cursor.fetchone())
	db.close()
	try:
		db = sqlite3.connect(":memory:")
		raw = data.read()
		db.deserialize(raw)
		db.execute("PRAGMA schema_version;")
		db.close()
		with open(os.path.join(current_app.root_path, "data.db"), "wb") as f:
			f.write(raw)
		db = sqlite3.connect("data.db")
		cursor = db.cursor()
		cursor.row_factory = sqlite3.Row
		cursor.execute("SELECT * FROM users WHERE username='admin'")
		row = cursor.fetchone()
		if row:
			cursor.execute(f"""UPDATE users SET {"=?, ".join([i for i in admin_data.keys()])+"=? "} WHERE username='admin'""",
				tuple([i for i in admin_data.values()]))
		else:
			cursor.execute(f"""INSERT INTO users ({",".join([i for i in admin_data.keys()])}) VALUES({",".join(["?" for _ in range(len(admin_data))])})""",
				tuple([i for i in admin_data.values()]))
		db.commit()
		db.close()
		return jsonify({"success": 1}), 200
	except sqlite3.Error as e:
		print(e)
		return jsonify({"error": "Incompatible data"}), 400