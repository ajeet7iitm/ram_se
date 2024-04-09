from flask_restful import Resource, request, abort
import requests
from flask import jsonify
from datetime import datetime
from dateutil import tz, parser
from application.models import *
from application.models import  db
from application.routes import token_required
from application.workers import celery
from celery import chain
from application.tasks import send_email, response_notification
from datetime import datetime, timedelta
import jwt
from .config import Config
from werkzeug.exceptions import HTTPException 
from application import index

#global variables permanent "unique for each user"
global_api_key="805203cb88be4b6020394bb489667f1052bc2fb93ad1d66cc836f2dbfd0c69af"
global_api_username="21f1000907"
headers = {
                #'X-CSRF-Token': csrf_token,
                "Api_Key": global_api_key,
                "Api_Username": global_api_username
            }

class Login(Resource):
    def post(self):
        flag=False
        if request.is_json:
            email = request.json["email"]
            password = request.json["password"]
        else:
            email = request.form["email"]
            password = request.form["password"]
        test = User.query.filter_by(email=email).first()
        if(test is None):
            test=User.query.filter_by(username=email).first()
        if(test is None):
            test=User.query.filter_by(discourse_id=email).first()
        # print(test)
        if (test is None):
            abort(409,message="User does not exist")
        elif (test.password == password):
            if(test.status==1):
                id=str(test.discourse_id)
                print(id)
                x=requests.get(f"http://localhost:4200/admin/users/{id}.json",headers=headers)
                print("check1",x.json())
                if x.json():
                    out1=x.json()
                    did=out1['id']
                    duser=out1['username']
                    dname=out1['name']
                    print("update3")
                    y=requests.get(f"http://localhost:4200/u/{duser}/emails.json",headers=headers)
                    demail=y.json()["email"]
                    print(demail)
                    if (demail!=test.email or duser!=test.username):
                        test.email=demail
                        test.username=duser
                        test.name=dname
                        db.session.add(test)
                        db.session.commit()
                        flag=True
                        print("update4")

                token = jwt.encode({
                    'id': test.id,
                    'exp': datetime.utcnow() + timedelta(minutes=80)
                }, Config.SECRET_KEY, algorithm="HS256")
                # access_token = create_access_token(identity=email)
                # print(token)
            else:
                abort(401, message="Account is not activte, verify email")
            if(flag):
                return jsonify({"message":"User email and user_id has been updated, kindly use new discorse email or user_id from next time", "token":token,"user_id":test.user_id,"role":test.role_id})
            else:
                return jsonify({"message":"Loggedin successfully !", "token":token,"user_id":test.id,"role":test.role})
        else:
            abort(401, message="Bad Email or Password")

