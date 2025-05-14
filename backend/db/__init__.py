from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect
from datetime import datetime
import json
import os
from dotenv import load_dotenv
from db.models import db, User, PEMalware, PEComponents
from db.data import PE_COMPONENTS, PE_MALWARE_CAPABILITIES, PE_MALWARE_FAMILY,APPLICATION_USERS,PE_MALWARE_REMEDIATION, PE_MALWARE_INFO

# load data from env 
load_dotenv()

def get_db(app=None):
    if app:
        _configure_db(app)
    return db


def _configure_db(app):
    db_name = os.getenv('DB_NAME', 'PEyeDetect.db')
    base_dir = os.path.abspath(os.path.dirname(__file__))
    db_path = os.path.join(base_dir, db_name)

    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

def initialize_db(app):
    with app.app_context():
        inspector = inspect(db.engine)

        if 'pe_malware' not in inspector.get_table_names():
            print("Creating 'pe_malware' table")
            db.create_all()

            for malware_id, malware_family in PE_MALWARE_FAMILY.items():
                capabilities = json.dumps(PE_MALWARE_CAPABILITIES.get(malware_id))
                remedy = json.dumps(PE_MALWARE_REMEDIATION.get(malware_id))
                info = PE_MALWARE_INFO.get(malware_id) 

                entry = PEMalware(
                    id=malware_id,
                    malware_family=malware_family,
                    capabilities=capabilities,
                    remedy=remedy,
                    info = info
                )
                db.session.add(entry)
            db.session.commit()

        if 'pe_components' not in inspector.get_table_names():
            print("Creating 'pe_components' table")
            db.create_all()

            for component_id, compoments in PE_COMPONENTS.items():
                component_name = compoments['component_name']
                description = json.dumps(compoments['description'])
                entry = PEComponents(
                    id=component_id,
                    component_name=component_name,
                    description=description,
                )
                db.session.add(entry)
            db.session.commit()

        if 'users' not in inspector.get_table_names():
            print("Creating 'users' table")
            db.create_all()

            for key, value in APPLICATION_USERS.items():
                
                entry = User(
                    # id=key,
                    first_name=value['first_name'],
                    last_name=value['last_name'],
                    email=value['email'],
                    password_hash=value['password_hash'],
                    role=value['role']
                )
                db.session.add(entry)
            db.session.commit()

        if 'prediction_history' not in inspector.get_table_names():
            print("Creating 'prediction_history' table")
            db.create_all()
