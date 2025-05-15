from flask import Flask, request, jsonify, Response
from flask_cors import CORS 
import os
import numpy as np
import tensorflow as tf
import joblib
from user_service import check_user_login, register_user, get_prediction_history_by_user
from db import get_db, initialize_db
from werkzeug.utils import secure_filename
import json
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from dotenv import load_dotenv
from predict import predict_pe_file
from datetime import timedelta

app = Flask(__name__)
CORS(app)

# Init DB and create tables
db = get_db(app)
initialize_db(app)


# load data from env 
load_dotenv()


app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

hours_str = os.getenv('LOGIN_VALIDITY_HOURS', '1')  # default to '1' hour if not set
hours = int(hours_str)

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=hours)
jwt = JWTManager(app)


#load models
ensemble_model = joblib.load('ml-models/ensemble_hybrid_model.joblib')

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')
    user = check_user_login(email, password)
    if(user['status']):
        access_token = create_access_token(identity=str(user['id']))
        return jsonify({"status":"success","user_id": user['id'], "token": access_token, "role": user['role'], "name":user['name']}), 200
    else:
        return jsonify({"status":"error","message": "Incorrect email or password"}), 401


@app.route('/register', methods=['POST'])
def register():
    user = register_user(request)
    if(user['status']):
        return jsonify({"status":"success","message": "user registered in system", "user_id": user['id'], "role": user['role'], "name":user['name']}), 200
    else:
        return jsonify({"status":"error","message": user['error_message']}), 401
    
@app.route('/model/user-prediction-history', methods=['GET'])
@jwt_required()
def get_single_user_prediction_history():
    # extract id from token
    user_id = get_jwt_identity()  

    predictions = get_prediction_history_by_user(user_id)

    return jsonify({"status":"success",
                        "message": "prediction history for user", 
                        "count": len(predictions), 
                        "prediction_history":predictions}), 200
    

@app.route('/predict', methods=['POST'])
def make_prediction():

    try:
        # registered users
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()  
    except Exception:
        # unregistered users
        user_id=None

    file = request.files.get("file")
    if not file:
        return jsonify({"status":"error","message": "PE file is required."}), 400

    filename = secure_filename(file.filename)
    if not filename:
        return jsonify({"status":"error","message": "Invalid file name."}), 400
    
    base_dir = os.path.abspath(os.path.dirname(__file__))
    pe_path = os.path.join(base_dir, UPLOAD_FOLDER, filename)

    try:
        # save uploaded file
        file.save(pe_path)
        print(pe_path)

        malware_class, prob, file_detais, remedy, capabilities, info = predict_pe_file(pe_path,ensemble_model,user_id)
    

        if(malware_class==0):
            # legitimate

            # response
            result = {
                "status":"ok",
                "login": True if user_id else False,
                "message":"legitimate",
                "probability":prob,
                "risk": 1-prob,
                "file_details":file_detais
            }
        else:

            # determine the malware family

            # response
            result = {
                "status":"ok",
                "login": True if user_id else False,
                "message":"malware",
                "malware_class": malware_class,
                "probability":prob,
                "risk": 1-prob,
                "info": info,
                "file_details":file_detais,
                "capabilities":capabilities,
                "info":info,
                "remedy":remedy
            }



    except Exception as e:
        return jsonify({"status":"error", "message": str(e)}), 500
    finally:
        if(pe_path):
            # clean up temp files
            # if os.path.exists(pe_path):
                # os.remove(pe_path)
            print("cleaned")

    # manual serialization
    response_data = json.dumps(result, sort_keys=False)  # preserve insertion order
    return Response(response_data, mimetype='application/json')


if __name__ == '__main__':
    app.run(debug=True)