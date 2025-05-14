from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f"<User {self.email}>"

class PEMalware(db.Model):
    __tablename__ = 'pe_malware'
    id = db.Column(db.Integer, primary_key=True)
    malware_family = db.Column(db.String(100), unique=True, nullable=False)
    capabilities = db.Column(db.Text, nullable=False)
    remedy = db.Column(db.Text, nullable=False)
    info = db.Column(db.Text, nullable=False)
    

    @classmethod
    def get_all(cls):
        return cls.query.all()

class PEComponents(db.Model):
    __tablename__ = 'pe_components'
    id = db.Column(db.Integer, primary_key=True)
    component_name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)


class PredictionHistory(db.Model):
    __tablename__ = 'prediction_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    malware_class = db.Column(db.Integer, nullable=False)
    confidence_score = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    # sha256 may also be required
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'malware_class': self.malware_class,
            'confidence_score': self.confidence_score,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }