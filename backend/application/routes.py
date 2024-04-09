from application import app
from flask import request, jsonify, render_template, redirect
from .models import *
from flask_restful import Resource, request, abort
from datetime import datetime, timedelta
from flask_restful import Resource, request, abort
from flask import jsonify
from datetime import datetime
from dateutil import tz, parser
from application.models import *
from application.models import  db
from application.workers import celery
from celery import chain
from application.tasks import send_email, response_notification
from datetime import datetime, timedelta
import jwt
from .config import Config
from werkzeug.exceptions import HTTPException 
from application import index
from application.email import send_verification_email, send_email
import requests
from application.mail2 import send_message
from application.mail3 import index
#remove this local token1 and activate get header section from original frontend
local_token1="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZXhwIjoxNzEyNDk2Mzg2fQ.GSOl207gygbWF55PYxYG-mKdC3Qjr9ggU89pCtoTQQw"

#global variables permanent "unique for each user"
global_api_key="805203cb88be4b6020394bb489667f1052bc2fb93ad1d66cc836f2dbfd0c69af"
global_api_username="21f1000907"
headers = {
        "Api_Key":global_api_key,
        "Api_Username": global_api_username
    }
@app.route('/test1')
def test1():
    id=str(2)
    data={
          "id":id
    }
    x=requests.get(f"http://localhost:4200/admin/users/{id}.json",headers=headers)
    return x.json()



def token_required(function):
	@functools.wraps(function)
	def loggedin(*args,**kwargs):
		auth_token=None
		try:
			auth_token = request.headers['secret_authtoken']
		
		except:
			return jsonify({"status":'unsuccessful, missing the authtoken'})
		#auth_token =local_token1
		try: 
			output = jwt.decode(auth_token,Config.SECRET_KEY,algorithms=["HS256"])
			#print(output)
			user = User.query.filter_by(id = output["id"]).first()
		except:
			return jsonify({"status":"failure, your token details do not match"})
		
		return function(user,*args,**kwargs)
	return loggedin


@app.route("/")
def home():
    return 'sitaram'

@app.route("/users", methods=["GET"])
@token_required
def get_users(current_user):
    print(current_user)
    users = User.query.all()
    results = [
        {
            "user_id": user.id,
            "user_name": user.username,
            #"name": user.name,
            "email_id": user.email,
            "role_id": user.role
        } for user in users]
    return jsonify(results)


#using temporary html template for login
@app.route("/sitaram", methods=["GET", "POST"])
def home_ram():      
    return render_template("login.html")
#using temporary html template for signup
@app.route("/signup", methods=["GET", "POST"])
def signuppage():      
    return render_template("signup.html")
#temporary send mail system
@app.route('/send1')
def ram1():
    return send_email()
@app.route('/send2')
def ram2():
      print("doing")
      return send_message("005ajeet@gmail.com","sitaram","mahadev")
@app.route('/send3')
def ram3():
      print("doing")
      return index()


# @app.route("/signin", methods=["GET", "POST"])
# def post1():
#     email = request.form["email"]
#     password = request.form["password"]
#     test = User.query.filter_by(email_id=email).first()
#     # print(test)
#     if (test is None):
#         abort(409,message="User does not exist")
#     elif (test.password == password):
#         if(test.status==1):
#             token = jwt.encode({
#                 'user_id': test.user_id,  
#                 'exp': datetime.utcnow() + timedelta(minutes=300)
#             }, Config.SECRET_KEY, algorithm="HS256")
#             # access_token = create_access_token(identity=email)
#             # print(token)
#             global local_token
#             local_token=token
#             print(local_token)
#         else:
#              return("verify email")
#         return jsonify({"message":"Login Succeeded!", "token":token,"user_id":test.user_id,"role":test.role_id})
#     else:
#         abort(401, message="Bad Email or Password")



# from application.workers import celery
# from application.tasks import send_email
# @app.route("/email", methods=["POST"])
# def post_email():
#     html = request.get_json()['html']
#     email = request.get_json()['email']
#     subject = request.get_json()['subject']
#     send_email.s(eid=email, html=html, subject=subject).apply_async()
#     return jsonify({'message': 'success'})

# from application.workers import celery
# from application.tasks import unanswered_ticket_notification
# @app.route("/notification")
# def get_notif():
#     unanswered_ticket_notification.s().apply_async()
#     return "OK"