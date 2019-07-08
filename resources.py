from flask_restful import Resource, reqparse
from models import UserModel, RevokedTokenModel, UserAccountInfoModel
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
import requests

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
parser_b.add_argument('spreadsheet_target', help = 'This field cannot be blank', required = True)

class UserAddSpreadsheet(Resource):
    @jwt_required
    def post(self):
        data = parser_b.parse_args()
        
        if UserModel.find_by_username(data['username']):
            if UserAccountInfoModel.find_by_username(data['username']):
                return {'message': 'User {} already has a spreadsheet'.format(data['username'])}

            new_accountinfo = UserAccountInfoModel(
                username = data['username'],
                spreadsheet = data['spreadsheet'],
                spreadsheet_target = data['spreadsheet_target']
            )

            try:
                new_accountinfo.save_to_db()
                return {
                    'message': 'Spreadsheet {} was added'.format(new_accountinfo.username),
                    'spreadsheet': new_accountinfo.spreadsheet,
                    'spreadsheet_target': new_accountinfo.spreadsheet_target
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

parser_c = reqparse.RequestParser()
parser_c.add_argument('username', help = 'This field cannot be blank', required = True)
parser_c.add_argument('ml_type', help = 'This field cannot be blank', required = True)

class UserTrainModel(Resource):
    def post(self):
        data = parser_c.parse_args()

        spreadsheet = UserAccountInfoModel.find_spreadsheet_by_username(data['username'])
        spreadsheet_target = UserAccountInfoModel.find_target_by_username(data['username'])

        model_type = data['ml_type']

        if model_type == 'regression':
            url = 'http://localhost:3000/linear'
        else:
            url = 'http://localhost:3000/logistic'

        if UserAccountInfoModel.find_by_username(data['username']):    
            try:
                print(UserAccountInfoModel.user_has_model(data['username']))
                if UserAccountInfoModel.user_has_model(data['username']):
                    datas = {
                        'username': data['username'],
                        'spreadsheet': spreadsheet,
                        'spreadsheet_target' : spreadsheet_target,
                        'bucket_status' : 'old'
                    }
                else:
                    print("sup")
                    datas = {
                        'username': data['username'],
                        'spreadsheet': spreadsheet,
                        'spreadsheet_target' : spreadsheet_target,
                        'bucket_status' : 'new'
                    }
                
                response = requests.post(url, data=datas)

                
                response_message = response.json()

                UserAccountInfoModel.add_model(data['username'], response_message['message'])

                return {'message': response_message['message']}
            
            except:
                return {'message': 'Something went wrong'}, 500
        
        else:
            return {'message': 'User doesnt exist'}


parser_d = reqparse.RequestParser()
parser_d.add_argument('username', help = 'This field cannot be blank', required = True)
parser_d.add_argument('ml_type', help = 'Thid field cannot be blank', required = True)

class UserPredictModel(Resource):
    def post(self):
        data = parser_d.parse_args()

        model = UserAccountInfoModel.find_model_by_username(data['username'])
        spreadsheet = UserAccountInfoModel.find_spreadsheet_by_username(data['username'])
        spreadsheet_target = UserAccountInfoModel.find_target_by_username(data['username'])

        ml_type = data['ml_type']

        if UserAccountInfoModel.find_by_username(data['username']):
            try:
                if ml_type == 'regression':
                    url = 'http://localhost:3000/predict/linear'
                else:
                    url = 'http://localhost:3000/predict/logistic'
                
                datas = {
                    'username' : data['username'],
                    'model' : model,
                    'spreadsheet' : spreadsheet,
                    'spreadsheet_target' : spreadsheet_target
                }

                response = requests.post(url, data=datas)
                response_message = response.json()

                return {'message' : response_message['message']}
            except:
                return {'message': 'Something went wrong'}, 500
        
        else:
            return {'message' : 'User doesnt exist'}