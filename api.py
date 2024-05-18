from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # Change this to a random secret key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Mock database
users_db = {}

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in users_db:
        return jsonify({"msg": "User already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    users_db[username] = hashed_password

    return jsonify({"msg": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    hashed_password = users_db.get(username)

    if hashed_password and bcrypt.check_password_hash(hashed_password, password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200

    return jsonify({"msg": "Invalid credentials"}), 401

@app.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    username = get_jwt_identity()
    hashed_password = users_db.get(username)

    if not bcrypt.check_password_hash(hashed_password, current_password):
        return jsonify({"msg": "Current password is incorrect"}), 401

    new_hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    users_db[username] = new_hashed_password

    return jsonify({"msg": "Password changed successfully"}), 200

if __name__ == '__main__':
    app.run(debug=True)
