from flask import Blueprint, current_app, Flask, request, render_template, jsonify, redirect
import sqlite3, random, re, os, bcrypt

auth_api = Blueprint("auth_api", __name__)

db = sqlite3.connect("data.db")
db.execute("""CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY NOT NULL UNIQUE,
	username TEXT NOT NULL UNIQUE,
	password TEXT NOT NULL,
	created DATETIME NOT NULL DEFAULT (datetime('now')),
	token INTEGER NOT NULL UNIQUE,
	status TEXT NOT NULL DEFAULT "unlocked",
	admin INTEGER NOT NULL DEFAULT 0
)""")
db.commit()
db.close()

def check_signed(cookies):
	if not cookies:
		return False
	if not cookies.get("user_token"):
		return False
	user_token = request.cookies.get("user_token")
	db = sqlite3.connect("data.db")
	db.row_factory = sqlite3.Row
	cursor = db.cursor()
	cursor.execute("SELECT * FROM users WHERE token=?", (user_token,))
	row = cursor.fetchone()
	db.close()
	if not row:
		return False
	return dict(row)

def check_fields(form, required_fields):
	for i in required_fields:
		if i not in form.keys():
			return jsonify({
				"error": "The above field was not submitted",
				"field": i
			}), 400
	for i in required_fields:
		if not form.get(i):
			return jsonify({
				"error": "The above field is empty",
				"field": i
			}), 400
	return False

@auth_api.route("/auth", methods=["GET", "POST"])
def auth():
	if check_signed(request.cookies):
		return redirect("/")
	if request.method == "GET":
		return render_template("auth.html")
	required_fields = ["username", "password"]
	error = check_fields(request.form, required_fields)
	if error:
		return error
	username = request.form.get("username").strip()
	password = request.form.get("password")
	db = sqlite3.connect("data.db")
	db.row_factory = sqlite3.Row
	cursor = db.cursor()
	cursor.execute("SELECT password FROM users WHERE username=?", (username,))
	row = cursor.fetchone()
	if not row:
		db.close()
		return jsonify({
			"error": "The username is invalid",
			"field": "username"
		}), 400
	row = dict(row)
	if not bcrypt.checkpw(
		password.encode("utf-8"),
		row.get("password").encode("utf-8")
	):
		db.close()
		return jsonify({
			"error": "The password is invalid",
			"field": "password"
		}), 400
	while True:
		user_token = random.randint(1000000000, 9999999999)
		cursor.execute("SELECT * FROM users WHERE token=?", (user_token,))
		row = cursor.fetchone()
		if not row:
			break
	cursor.execute("UPDATE users SET token=? WHERE username=?", (user_token, username))
	db.commit()
	db.close()
	return jsonify({
		"success": 1,
		"user_token": user_token
	}), 200