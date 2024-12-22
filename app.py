import os
import stripe
from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from dotenv import load_dotenv
from flask_cors import CORS

load_dotenv()

app = Flask(__name__)

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

@app.route('/checkout', methods=['POST'])
def checkout():
    try:
        line_items = request.json.get('lineItems')
        if not line_items:
            return jsonify({"error": "No line items provided"}), 400

        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=line_items,
            mode='payment',
            success_url="http://localhost:5173/success",
            cancel_url="http://localhost:5173/cancel",
        )

        return jsonify({'id': session.id})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

CORS(app, origins=["http://localhost:5173"], methods=["GET", "POST", "OPTIONS"], allow_headers=["Content-Type", "Authorization"])

app.config['MONGO_URI'] = os.getenv('MONGO_URI')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

def email_exists(email):
    user = mongo.db.users.find_one({"email": email})
    return user is not None

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    if not data.get('email') or not data.get('password'):
        return jsonify({"message": "Email and password are required"}), 400

    if email_exists(data['email']):
        return jsonify({"message": "Email already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    mongo.db.users.insert_one({
        "email": data['email'],
        "password": hashed_password
    })

    return jsonify({"success": True, "message": "User created successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data.get('email') or not data.get('password'):
        return jsonify({"message": "Email and password are required"}), 400

    user = mongo.db.users.find_one({"email": data['email']})
    if not user or not bcrypt.check_password_hash(user['password'], data['password']):
        return jsonify({"message": "Invalid credentials"}), 401

    access_token = create_access_token(identity=str(user['_id']))
    
    return jsonify({"message": "Login successful", "access_token": access_token})

if __name__ == '__main__':
    app.run(debug=True)
