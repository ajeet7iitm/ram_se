from flask_restful import Resource, request, abort
import requests
from flask import jsonify
from datetime import datetime
from dateutil import tz, parser
from application.models import *
from application.models import db
from application.routes import token_required
from application.workers import celery
from celery import chain
from application.tasks import send_email, response_notification
from datetime import datetime, timedelta
import jwt
from .config import Config
from werkzeug.exceptions import HTTPException 
from application import index
import secrets
from application.email import send_verification_email, send_email


#global variables permanent "unique for each user"
global_api_key="805203cb88be4b6020394bb489667f1052bc2fb93ad1d66cc836f2dbfd0c69af"
global_api_username="21f1000907"
headers = {
        #'X-CSRF-Token': csrf_token,
        "Api_Key": global_api_key,
        "Api_Username": global_api_username
    }

class Sitaram(Resource): 
    #@token_required
    def get(self):
        x=requests.get("http://localhost:4200/u/005ajeet.json")  
        return x.json()
    
#for registering new user using discourse data
class Registration(Resource):
    def post(self):
        if request.is_json:
            email = request.json["email"]
            password = request.json["password"]
        else:
            email = request.form["email"]
            password = request.form["password"]
        email=email
        check1=User.query.filter_by(email=email).first()
        if(check1 and check1.status==0):
            # verification_token = secrets.token_urlsafe(16)
            # print(verification_token)
            # send_verification_email(email, verification_token)
            #abort(400, message = "alreary registerd, verify your email")
            return jsonify({"Message":"alreary registerd, verify your email"})
        elif(check1 and check1.status==1):
            #abort(404, message = "already an active user, login")
            return jsonify({"message":"already an active user, login"})
        flag=["active","seen","last_emailed"]
        data={
            "show_emails": "true",
            "email":email
        }
        x=requests.get(f"http://localhost:4200/admin/users/list/{flag}.json",params=data,headers=headers)
        if x.json():
            out1=x.json()
            did=out1[0]['id']
            duser=out1[0]['username']
            dname=out1[0]['name']
            user1=User(username=duser,
                       name=dname,
                       password=password,
                       email=email,
                       role=1,
                       discourse_id=did
            )
            db.session.add(user1) 
            db.session.commit()
            # verification_token = secrets.token_urlsafe(16)
            # send_verification_email(email, verification_token)
            return jsonify({"id":did,"name":dname,"user":duser,"email":email,"role":1,"message": "do email verification to login","code":200})
        else:
            return jsonify({"Message":"You are not authorized to access this feature."})
            #abort(400, message = "You are not authorized to access this feature.")

#email verification to activate and deactivate      
class Verification(Resource):
    def get(self):
        email="005ajeet@gmail.com"
        user1=User.query.filter_by(email=email).first()
        print(user1)
        if(user1.status==0):
            user1.status=1
            db.session.add(user1)
            db.session.commit()  
            return jsonify({"message":"activated"})
        elif(user1.status==1):
            user1.status=0
            db.session.add(user1)
            db.session.commit() 
            return jsonify({"message":"already activate"})
         



class Discourse_post(Resource):
    @token_required
    def get(user,self):
        data = {
            
            "title": "testing apis with ajeet and george",
            "raw": "Love encompasses a range of strong and positive emotional and mental states, from the most sublime virtue or good habit, the deepest interpersonal affection, to the simplest pleasure.[1] An example of this range of meanings is that the love of a mother differs from the love of a spouse, which differs from the love for food. Most commonly, love refers to a feeling of strong attraction and emotional attachment",
            "topic_id": 5,
            "category": 0,
           
            # Add other data parameters as needed
        }
        # Sending the POST request
        response = requests.post("http://localhost:4200/posts.json", json=data,headers=headers)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            return {"message": "POST request successful",
                    "response": response.json()}, 200
        else:
            return {"message": "POST request failed",
                    "response": response.json()}, 500
