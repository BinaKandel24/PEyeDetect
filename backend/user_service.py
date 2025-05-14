from db.models import db, User, PredictionHistory
from werkzeug.security import check_password_hash, generate_password_hash
import re
from datetime import datetime
from zoneinfo import ZoneInfo

def check_user_login(email, password):
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password_hash, password):
        return {
            "status": True,
            "id": user.id,
            "name": user.first_name,
            "role": user.role
        }
    else:
        return {
            "status": False
        }


def register_user(request):
    # Password validation regex:
    # - Minimum 6 characters
    # - At least one uppercase letter
    # - At least one lowercase letter
    # - At least one special character
    password_pattern = re.compile(
        r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[\W_]).{6,}$'
    )

    data = request.get_json()
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')
    re_password = data.get('re_password')
    role = "user"
    

    if not all([first_name, last_name, email, password, re_password]):
        return {"status": False, "error_message": "Missing required fields"}

    if User.query.filter_by(email=email).first():
        return {"status": False, "error_message": "Email already registered"}

    if not password_pattern.match(password):
        return {"status": False, "error_message": "Password requirements not met"}

    if (password!=re_password):
        return {"status": False, "error_message": "Passowrds don't match"}

    new_user = User(first_name=first_name, last_name=last_name, email=email, role=role, 
                    password_hash=generate_password_hash(password))

    db.session.add(new_user)
    db.session.commit()
    return {
        "status": True,
        "id": new_user.id,
        "role": new_user.role,
        "name": f"{new_user.first_name} {new_user.last_name}"
    }


def save_malware_scan_result(user_id, scan_result):
    local_now = datetime.now(ZoneInfo("Asia/Kathmandu"))
    local_now = datetime.now(ZoneInfo("Australia/Melbourne"))
    

    new_prediction = PredictionHistory(user_id= user_id, 
                        file_name=scan_result['file_details']['file_name'],
                        file_size=scan_result['file_details']['file_size_bytes'],
                        malware_class=scan_result['malware_class'],
                        confidence_score = scan_result['confidence'],
                        timestamp = local_now)

    db.session.add(new_prediction)
    db.session.commit()
    

def get_prediction_history_by_user(user_id):
    is_user_admin = is_admin(user_id)

    if(is_user_admin):
        history = PredictionHistory.query.all()
    else:    
        history = PredictionHistory.query.filter_by(user_id=user_id).all()
    
    history_dicts = [record.to_dict() for record in history]
    print(history_dicts)
    return history_dicts


def is_admin(user_id):
    user = User.query.filter_by(id=user_id).first()
    if(user.role=='admin'):
        return True
    else:
        return False
