from flask_restful import Resource, reqparse
from models import UserModel, RevokedTokenModel, UserAccountInfoModel
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)

parser = reqparse.RequestParser()
parser.add_argument('username', help = 'This field cannot be blank', required = True)
parser.add_argument('password', help = 'This field cannot be blank', required = True)


class UserRegistration(Resource):
    def post(self):
        data = parser.parse_args()
        
        if UserModel.find_by_username(data['username']):
            return {'message': 'User {} already exists'.format(data['username'])}
        
        new_user = UserModel(
            username = data['username'],
            password = UserModel.generate_hash(data['password'])
        )
        
        try:
            new_user.save_to_db()
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                'message': 'User {} was created'.format(data['username']),
                'access_token': access_token,
                'refresh_token': refresh_token
                }
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogin(Resource):
    def post(self):
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data['username'])

        if not current_user:
            return {'message': 'User {} doesn\'t exist'.format(data['username'])}
        
        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token,
                'refresh_token': refresh_token
                }
        else:
            return {'message': 'Wrong credentials'}


class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Access token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return {'access_token': access_token}


class AllUsers(Resource):
    def get(self):
        return UserModel.return_all()
    
    def delete(self):
        return UserModel.delete_all()


class SecretResource(Resource):
    @jwt_required
    def get(self):
        return {
            'answer': 42
        }

parser_b = reqparse.RequestParser()
parser_b.add_argument('username', help = 'This field cannot be blank', required = True)
parser_b.add_argument('spreadsheet', help = 'This field cannot be blank', required = True)

class UserAddSpreadsheet(Resource):
    @jwt_required
    def post(self):
        data = parser_b.parse_args()
        
        if UserModel.find_by_username(data['username']):
            if UserAccountInfoModel.find_by_username(data['username']):
                return {'message': 'User {} already has a spreadsheet'.format(data['username'])}

            new_accountinfo = UserAccountInfoModel(
                username = data['username'],
                spreadsheet = data['spreadsheet']
            )

            try:
                new_accountinfo.save_to_db()
                return {
                    'message': 'Spreadsheet {} was added'.format(data['username']),
                    'spreadsheet': data['spreadsheet']
                    }
            except:
                return {'message': 'Something went wrong'}, 500
        
        else:
            return {'message': 'This user doesnt exist'}

class UserChangeSpreadsheet(Resource):
    @jwt_required
    def post(self):
        data = parser_b.parse_args()
        
        if UserAccountInfoModel.find_by_username(data['username']):
            try:
                UserAccountInfoModel.change_spreadsheet(data['username'], data['spreadsheet'])
                return {
                    'message': 'Spreadsheet {} was changed'.format(data['username']),
                    'spreadsheet': data['spreadsheet']
                    }
            except:
                return {'message': 'Something went wrong'}, 500
        
        else:
            return {'message': 'This user doesnt exist'}

class AllSpreadsheets(Resource):
    def get(self):
        return UserAccountInfoModel.return_all()
    
    def delete(self):
        return UserAccountInfoModel.delete_all()
