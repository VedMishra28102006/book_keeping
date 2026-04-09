from flask import Blueprint, current_app, Flask

app = Flask(__name__)
with app.app_context():
	from apis.auth_api import auth_api
	app.register_blueprint(auth_api)
	from apis.accounting_api import accounting
	app.register_blueprint(accounting)
	from apis.admin_api import admin
	app.register_blueprint(admin)

if __name__ == "__main__":
	app.run(host="0.0.0.0", port=10000)
