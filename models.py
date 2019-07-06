from run import db
from passlib.hash import pbkdf2_sha256 as sha256

class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(120), nullable = False)
    
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
    
    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username = username).first()
    
    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'username': x.username,
                'password': x.password
            }
        return {'users': list(map(lambda x: to_json(x), UserModel.query.all()))}

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)
    
    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)

class RevokedTokenModel(db.Model):
    __tablename__ = 'revoked_tokens'
    id = db.Column(db.Integer, primary_key = True)
    jti = db.Column(db.String(120))
    
    def add(self):
        db.session.add(self)
        db.session.commit()
    
    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti = jti).first()
        return bool(query)


class UserAccountInfoModel(db.Model):
    __tablename__ = 'accountinfo'
    username = db.Column(db.String(255), db.ForeignKey('users.username'), primary_key = True)
    spreadsheet = db.Column(db.String(255), nullable = True)
    model = db.Column(db.String(255), nullable = True)

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username = username).first()

    @classmethod
    def find_spreadsheet_by_username(cls, username):
          return cls.query.filter_by(username = username).first().spreadsheet

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'username': x.username,
                'spreadsheet': x.spreadsheet,
                'model' : x.model
            }
        return {'accountinfo': list(map(lambda x: to_json(x), UserAccountInfoModel.query.all()))}
    
    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}
    
    @classmethod
    def change_spreadsheet(cls, username, spreadsheet):
        user = UserAccountInfoModel.query.filter_by(username=username).first()
        user.spreadsheet = spreadsheet
        db.session.commit()

    @classmethod
    def add_model(cls, username, model):
        user = UserAccountInfoModel.query.filter_by(username=username).first()
        user.model = model
        db.session.commit()

    @classmethod
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

