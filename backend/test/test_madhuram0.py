import sys
import os 
from datetime import datetime

# Append parent directory to sys.path to enable imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import requests
from datetime import datetime
import pytest
from application import app
import requests
from flask import json
#import db models here
import sys 
import os
from application.models import *
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()
import requests
from flask import json


BASE="http://127.0.0.1:5000"
url_login = BASE+"/login"
url_tt_all = BASE+"/api/ticket_All"
url_getResTime = BASE+"/api/getResolutionTimes"
url_flagPost = BASE+"/api/flaggedPosts"
url_RUser = BASE+"/api/respUser"
url_getRTic = BASE+"/api/getResponseAPI_by_ticket"
url_RTick = BASE+"/api/respTicket"
url_RDel = BASE+"/api/respRespDel/2/8"
url_RR = BASE+ "/api/respResp"
url_Category = BASE+"/api/category"
url_ImportResourceUser = BASE+"/api/importUsers"
url_faq = BASE+"/api/faq"
url_delete_faq = url_faq+'/2'
url_tick = BASE+"/api/ticket"
url_delete_ticket = url_tick+"/3"
url_user = BASE+'/api/user'
url_delete_User = url_user+"/7"

def token_login_student():
    url=BASE+"/login"
    data={"email":"maddy.bohr@trainstore.org","password":"madhuram"}
    response=requests.post(url,data=data)
    return response.json()["token"]

def token_login_admin():
    url=BASE+"/login"
    data={"email":"saurav@saurav.com","password":"saurav"}
    response=requests.post(url,data=data)
    return response.json()["token"]

def token_login_manager():
    url = BASE+"/login"
    data = {"email": "leader@king.com", "password": "leader"}
    response = requests.post(url, data = data)
    return response.json()["token"]

def token_login_support_agent():
    url=BASE+"/login"
    data={"email":"visist@visist.com","password":"visist"}
    response=requests.post(url,data=data)
    return response.json()["token"]

#post request for class LoginAPI

def test_post_Login_valid_credentials():
    # Assume you have a valid user in your database
    user = User(email_id="testing@example.com", password="sitaram")
    db.session.add(user)
    db.session.commit()

    # Create a request with valid credentials
    data = {
        "email": "testing@example.com",
        "password": "sitaram"
    }
    response = requests.post(url_login, json=data)

    # Check if the response is successful and contains the expected data
    assert response.status_code == 200
    assert "token" in response.json()
    assert "user_id" in response.json()
    assert "role" in response.json()
    assert response.json()["message"] == "Login Succeeded!"

def test_post_Login_invalid_email():
    # Create a request with invalid email
    data = {
        "email": "invalid@example.com",
        "password": "sitaram"
    }
    response = requests.post(url_login, json=data)

    # Check if the response indicates bad email or password
    assert response.status_code == 401
    assert response.json()["message"] == "Bad Email or Password"

def test_post_Login_invalid_password():
    # Assume you have a valid user in your database
    user = User(email_id="testing@example.com", password="sitaram")
    db.session.add(user)
    db.session.commit()

    # Create a request with invalid password
    data = {
        "email": "testing@example.com",
        "password": "wrongpassword"
    }
    response = requests.post(url_login, json=data)

    # Check if the response indicates bad email or password
    assert response.status_code == 401
    assert response.json()["message"] == "Bad Email or Password"

#get request for class TicketAPI

def test_ticket_student_get():
    header={"secret_authtoken":token_login_student()}
    request=requests.get(url_tick,headers=header)
    ticket=Ticket.query.filter_by(creator_id=1).all()
    response=request.json()
    response=response['data']
    assert request.status_code==200
    for i in ticket:
        for j in response: 
            if(j["ticket_id"]==i.ticket_id):
                assert j["creator_id"]==i.creator_id
                assert j["title"]==i.title
                assert j["description"]==i.description
                assert j["number_of_upvotes"]==i.number_of_upvotes
                assert j["is_read"]==i.is_read
                assert j["is_open"]==i.is_open
                assert j["is_FAQ"]==i.is_FAQ
                assert j["is_offensive"]==i.is_offensive
                assert j["rating"]==i.rating

def test_ticket_admin_get():
    header={"secret_authtoken":token_login_admin()}
    request=requests.get(url_tick,headers=header)
    assert request.status_code==403
    
def test_ticket_support_agent_get():
    header={"secret_authtoken":token_login_support_agent()}
    request=requests.get(url_tick,headers=header)
    assert request.status_code==403

#post request for class TicketAPI

def test_ticket_student_post():
    header={"secret_authtoken":token_login_student(),"Content-Type":"application/json"}
    data={
        "title":"test1234",
        "description":"hi",
        "number_of_upvotes":13,
        "is_read":0,
        "is_open":1,
        "is_offensive":0,
        "is_FAQ":0
        }
    data=json.dumps(data)
    response=requests.post(url_tick,data=data,headers=header)
    assert response.status_code==200
    response_get=requests.get(url_tick,headers=header)
    response_get=response_get.json()
    response_get=response_get['data']
    for i in response_get:
        if(i["title"]=="test1234"):
            assert i["description"]=="hi"
            assert i["number_of_upvotes"]==13
            assert i["is_read"]==0
            assert i["is_open"]==1
            assert i["is_offensive"]==0
            assert i["is_FAQ"]==0
   
def test_ticket_admin_post():
    header={"secret_authtoken":token_login_admin(),"Content-Type":"application/json"}
    data={
        "title":"test1234",
        "description":"hi",
        "number_of_upvotes":13,
        "is_read":0,
        "is_open":1,
        "is_offensive":0,
        "is_FAQ":0
        }
    data=json.dumps(data)
    response=requests.post(url_tick,data=data,headers=header)
    assert response.status_code==403
    
def test_ticket_support_agent_post():
    header={"secret_authtoken":token_login_support_agent(),"Content-Type":"application/json"}
    data={
        "title":"test1234",
        "description":"hi",
        "number_of_upvotes":13,
        "is_read":0,
        "is_open":1,
        "is_offensive":0,
        "is_FAQ":0
        }
    data=json.dumps(data)
    response=requests.post(url_tick,data=data,headers=header)
    assert response.status_code==403

#patch request for class TicketAPI

def test_ticket_title_student_patch():
    header={"secret_authtoken":token_login_student(),"Content-Type":"application/json"}
    payload={
        "ticket_id":3,
        "title":"test",
    }
    payload=json.dumps(payload)
    
    response=requests.patch(url_tick,data=payload,headers=header)
    assert response.status_code==200
    response_get=requests.get(url_tick,headers=header)
    response_get=response_get.json()
    response_get=response_get['data']
    for i in response_get:
        if(i["ticket_id"]==3):
            assert i["title"]=="test"
    
def test_ticket_admin_patch():
    header={"secret_authtoken":token_login_admin(),"Content-Type":"application/json"}
    payload={
        "ticket_id":3,
        "title":"test",
    }
    payload=json.dumps(payload)
    response=requests.patch(url_tick,data=payload,headers=header)
    assert response.status_code==403
    
def test_ticket_support_agent_patch():
    header={"secret_authtoken":token_login_support_agent(),"Content-Type":"application/json"}
    payload={
        "ticket_id":3,
        "title":"test",
    }
    payload=json.dumps(payload)
    response=requests.patch(url_tick,data=payload,headers=header)
    assert response.status_code==403

#delete request for class TicketAPI

def test_ticket_student_delete():
    header={"secret_authtoken":token_login_student(),"Content-Type":"application/json"}
    response=requests.delete(url_delete_ticket,headers=header)
    assert response.status_code==200
    ticket=Ticket.query.filter_by(ticket_id=3).first()
    assert ticket==None
    
def test_ticket_admin_delete():
    header={"secret_authtoken":token_login_admin(),"Content-Type":"application/json"}
    response=requests.delete(url_delete_ticket,headers=header)
    assert response.status_code==400
    
def test_ticket_support_agent_delete():
    header={"secret_authtoken":token_login_support_agent(),"Content-Type":"application/json"}
    response=requests.delete(url_delete_ticket,headers=header)
    assert response.status_code==400

#get request for class UserAPI

def test_user_student_get():
    header={"secret_authtoken":token_login_student()}
    response=requests.get(url_user,headers=header)
    assert response.status_code==403

def test_user_support_agent_get():
    header={"secret_authtoken":token_login_support_agent()}
    response=requests.get(url_user,headers=header)
    assert response.status_code==403
    
def test_user_admin_get():
    header={"secret_authtoken":token_login_admin()}
    response=requests.get(url_user,headers=header)
    assert response.status_code==200
    user=User.query.all()
    response=response.json()
    response=response['data']
    for i in user:
        for j in response:
            if(i.user_id==j['user_id']):
                assert i.user_name==j['user_name']
                assert i.email_id==j['email_id']
                assert i.role_id==j['role_id']

#post request for class UserAPI

def test_user_student_post():
    header={"secret_authtoken":token_login_student(),"Content-Type":"application/json"}
    data={
        "email_id":"test@test",
        "role_id":1
    }
    data=json.dumps(data)
    response=requests.post(url_user,data=data,headers=header)
    assert response.status_code==403
    
def test_user_support_agent_post():
    header={"secret_authtoken":token_login_support_agent(),"Content-Type":"application/json"}
    data={
        "email_id":"test@test",
        "role_id":1
    }
    data=json.dumps(data)
    response=requests.post(url_user,data=data,headers=header)
    assert response.status_code==403
    
def test_user_admin_post():
    header={"secret_authtoken":token_login_admin(),"Content-Type":"application/json"}
    data={
        "email_id":"test@test",
        "role_id":1
    }
    data=json.dumps(data)
    response=requests.post(url_user,data=data,headers=header)
    assert response.status_code==200
    response_get=requests.get(url_user,headers=header)
    response_get=response_get.json()
    response_get=response_get['data']
    for i in response_get:
        if(i["email_id"]=="test@test"):
            assert i["role_id"]==1
    
#patch request for class UserAPI

def test_user_student_patch():
    header={"secret_authtoken":token_login_student(),"Content-Type":"application/json"}
    data={"user_name":"testing","user_id":7}
    data=json.dumps(data)
    response=requests.patch(url_user,data=data,headers=header)
    assert response.status_code==200

def test_user_support_agent_patch():
    header={"secret_authtoken":token_login_support_agent(),"Content-Type":"application/json"}
    data={"user_name":"testing","user_id":7}
    data=json.dumps(data)
    response=requests.patch(url_user,data=data,headers=header)
    assert response.status_code==200
    
def test_user_admin_patch():
    header={"secret_authtoken":token_login_admin(),"Content-Type":"application/json"}
    data={"user_name":"testing","user_id":7,"email_id":"test07@test"}
    data=json.dumps(data)
    response=requests.patch(url_user,data=data,headers=header)
    assert response.status_code==200
    response_get=requests.get(url_user,headers=header)
    response_get=response_get.json()
    response_get=response_get['data']
    for i in response_get:
        if(i["user_id"]==8):
            assert i["user_name"]=="testing"
            assert i["email_id"]=="test07@test"

#delete request for class UserAPI

def test_user_student_delete():
    header={"secret_authtoken":token_login_student(),"Content-Type":"application/json"}
    response=requests.delete(url_delete_User,headers=header)
    assert response.status_code==403
    
def test_user_support_agent_delete():
    header={"secret_authtoken":token_login_support_agent(),"Content-Type":"application/json"}
    response=requests.delete(url_delete_User,headers=header)
    assert response.status_code==403

def test_user_admin_delete():
    header={"secret_authtoken":token_login_admin(),"Content-Type":"application/json"}
    response=requests.delete(url_delete_User,headers=header)
    assert response.status_code==200
    user=User.query.filter_by(user_id=7).first()
    assert user==None
        
#get request for class FAQ

def test_faq_authorized_get():
    header={"secret_authtoken":token_login_student()}
    request=requests.get(url_faq,headers=header)
    faqs=FAQ.query.all()
    response=request.json()
    responses=response['data']
    assert request.status_code==200
    assert len(list(faqs)) == len(responses)
    for d in responses:
        for q in faqs:
            if q.ticket_id == d['ticket_id']:
                assert d['ticket_id'] ==  q.ticket_id
                assert d['category'] == q.category
                assert d['is_approved'] == q.is_approved

def test_faq_inauthenticated_get():
    request=requests.get(url_faq)
    response=request.json()
    assert request.status_code==200
    assert response['status']=='unsuccessful, missing the authtoken'

#post request for class FAQ

def test_faq_unauthorized_role_post():
    data = json.dumps({ "category": "operational","is_approved": False, "ticket_id": 2})
    header={"secret_authtoken":token_login_student(), "Content-Type":"application/json"}
    request=requests.post(url_faq,data=data, headers=header)
    assert request.status_code==403
    assert request.json()['message']=="Unauthorized"

def test_faq_inauthenticated_post():
    data = json.dumps({ "category": "operational","is_approved": False, "ticket_id": 2})
    header={"Content-Type":"application/json"}
    request=requests.post(url_faq,data=data)
    assert request.status_code==200
    assert request.json()['status']=='unsuccessful, missing the authtoken'

def test_faq_authorized_role_post_no_ticket_id():
    data = json.dumps({ "category": "operational","is_approved": False})
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.post(url_faq,data=data, headers=header)
    assert request.status_code==400
    assert request.json()['message']=="ticket_id is required and should be integer"

def test_faq_authorized_role_post_no_category():
    data = json.dumps({"is_approved": False, "ticket_id": 2})
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.post(url_faq,data=data, headers=header)
    assert request.status_code==400
    assert request.json()['message']=="category is required and should be string"

def test_faq_authorized_role_post_no_is_approved():
    data = json.dumps({ "category": "operational", "ticket_id": 2})
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.post(url_faq,data=data, headers=header)
    assert request.status_code==400
    assert request.json()['message']=="is_approved is required and should be boolean"

def test_faq_authorized_role_post_nonexistant_ticket_id():
    input_dict = { "category": "operational","is_approved": False, "ticket_id": 10000}
    data = json.dumps(input_dict)
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.post(url_faq,data=data, headers=header)
    assert request.status_code==400
    assert request.json()['message']=="ticket_id does not exist"
    assert FAQ.query.filter_by(ticket_id=input_dict["ticket_id"]).first() is None

def test_faq_authorized_role_post_nonexistant_category():
    input_dict = { "category": "abc","is_approved": False, "ticket_id": 2}
    data = json.dumps(input_dict)
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.post(url_faq,data=data, headers=header)
    assert request.status_code==400
    assert request.json()['message']=="category does not exist"
    assert FAQ.query.filter_by(ticket_id=input_dict["ticket_id"]).first() is None

def test_faq_authorized_role_post_invalid_isapproved():
    input_dict = { "category": "operational","is_approved": "abs", "ticket_id": 2}
    data = json.dumps(input_dict)
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.post(url_faq,data=data, headers=header)
    assert request.status_code==400
    assert request.json()['message']=="is_approved must be boolean"
    assert FAQ.query.filter_by(ticket_id=input_dict["ticket_id"]).first() is None

def test_faq_authorized_role_post_ticket_already_in_db():
    data = json.dumps({ "category": "operational","is_approved": False, "ticket_id": 1})
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.post(url_faq,data=data, headers=header)
    assert request.status_code==400
    assert request.json()['message']=="ticket already in FAQ"

def test_faq_authorized_role_post_valid_data():
    input_dict = { "category": "operational","is_approved": False, "ticket_id": 2}
    data = json.dumps(input_dict)
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.post(url_faq,data=data, headers=header)
    assert request.status_code==200
    assert request.json()['message']=="FAQ item added successfully"
    faq = FAQ.query.filter_by(ticket_id=2).first()
    assert input_dict["category"] == faq.category
    assert input_dict["is_approved"] == faq.is_approved

#patch request for class FAQ

def test_faq_inauthenticated_patch():
    request=requests.patch(url_delete_faq)
    assert request.status_code==200
    assert request.json()['status']=='unsuccessful, missing the authtoken'

def test_faq_unauthorized_role_patch():
    data = json.dumps({ "category": "operational","is_approved": False, "ticket_id": 2})
    header={"secret_authtoken":token_login_student(), "Content-Type":"application/json"}
    request=requests.patch(url_faq,data=data, headers=header)
    assert request.status_code==403
    assert request.json()['message']=="Unauthorized"

def test_faq_authorized_role_patch_no_ticket_id():
    data = json.dumps({ "category": "operational","is_approved": False})
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.patch(url_faq,data=data, headers=header)
    assert request.status_code==400
    assert request.json()['message']=="ticket_id is required and should be integer"

def test_faq_authorized_role_patch_no_category():
    input_dict = {"is_approved": False, "ticket_id": 1}
    data = json.dumps(input_dict)
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.patch(url_faq,data=data, headers=header)
    assert request.status_code==200
    assert request.json()['message']=="FAQ item updated successfully"
    assert input_dict["is_approved"]==FAQ.query.filter_by(ticket_id=1).first().is_approved

def test_faq_authorized_role_patch_no_is_approved():
    input_dict = { "category": "operational", "ticket_id": 1}
    data = json.dumps(input_dict)
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.patch(url_faq,data=data, headers=header)
    assert request.status_code==200
    assert request.json()['message']=="FAQ item updated successfully"
    assert input_dict["category"] == FAQ.query.filter_by(ticket_id=1).first().category

def test_faq_authorized_role_patch_nonexistant_ticket_id():
    data = json.dumps({ "category": "operational","is_approved": False, "ticket_id": 10000})
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.patch(url_faq,data=data, headers=header)
    assert request.status_code==400
    assert request.json()['message']=="ticket_id does not exist"
    assert not FAQ.query.filter_by(ticket_id=10000).first() 

def test_faq_authorized_role_patch_nonexistant_category():
    input_dict={ "category": "abc","is_approved": False, "ticket_id": 1}
    data = json.dumps(input_dict)
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.patch(url_faq,data=data, headers=header)
    assert request.status_code==400
    assert request.json()['message']=="category does not exist"
    assert input_dict["category"] != FAQ.query.filter_by(ticket_id=1).first().category


def test_faq_authorized_role_patch_invalid_isapproved():
    input_dict = { "category": "operational","is_approved": "abs", "ticket_id": 1}
    data = json.dumps(input_dict)
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.patch(url_faq,data=data, headers=header)
    assert request.status_code==400
    assert request.json()['message']=="is_approved must be boolean"
    assert input_dict["is_approved"] != FAQ.query.filter_by(ticket_id=1).first().is_approved


def test_faq_authorized_role_patch_valid_data():
    input_dict = { "category": "random","is_approved": False, "ticket_id": 1}
    data = json.dumps(input_dict)
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.patch(url_faq,data=data, headers=header)
    assert request.status_code==200
    assert request.json()['message']=="FAQ item updated successfully"
    faq = FAQ.query.filter_by(ticket_id=1).first()
    assert input_dict["category"] == faq.category
    assert input_dict["is_approved"] == faq.is_approved

#delete request for class FAQ

def test_faq_authorized_role_delete_valid():
    header={"secret_authtoken":token_login_admin()}
    request=requests.delete(url_delete_faq, headers=header)
    assert request.status_code==200
    assert request.json()['message']=="FAQ item deleted successfully"
    assert FAQ.query.filter_by(ticket_id=2).first() is None

def test_faq_unauthorized_role_delete():
    header={"secret_authtoken":token_login_student()}
    request=requests.delete(url_delete_faq, headers=header)
    assert request.status_code==403
    assert request.json()['message']=="Unauthorized"

def test_faq_inauthenticated_delete():
    request=requests.delete(url_delete_faq)
    assert request.status_code==200
    assert request.json()['status']=='unsuccessful, missing the authtoken'

def test_faq_authorized_role_delete_nonexistant_ticket():
    header={"secret_authtoken":token_login_admin()}
    request=requests.delete(url_faq+'/1000', headers=header)
    assert request.status_code==400
    assert request.json()['message']=="ticket_id does not exist"

def test_faq_authroized_role_delete_ticket_not_in_faq():
    header={"secret_authtoken":token_login_admin()}
    request=requests.delete(url_faq+'/2', headers=header)
    assert request.status_code==400
    assert request.json()['message']=="ticket_id is not in FAQ"

# post request for getResponseAPI_by_ticket

def test_post_getResponseAPI_by_ticket_unauthenticated():
    request=requests.post(url_getRTic)
    response=request.json()
    assert request.status_code==200
    assert response['status']=='unsuccessful, missing the authtoken'

def test_post_getResponseAPI_by_ticket_wrong_ticket_id():
    header={"secret_authtoken":token_login_manager(), "Content-Type":"application/json"}
    input_dict = { "ticket_id": 1000}
    data = json.dumps(input_dict)
    request=requests.post(url = url_getRTic, headers=header, data = data)
    response = request.json()
    assert request.status_code == 200
    assert response["data"] == []
    assert response["status"] == "success"

def test_post_getResponseAPI_by_ticket():
    #Checks everything except timestamps
    header={"secret_authtoken":token_login_manager(), "Content-Type":"application/json"}
    input_dict = { "ticket_id": 1}
    data = json.dumps(input_dict)
    request=requests.post(url = url_getRTic, headers=header, data = data)
    response = request.json()
    assert request.status_code == 200
    data = response["data"]
    responses = list(Response.query.filter_by(ticket_id = input_dict["ticket_id"]).all())
    assert len(responses) == len(data)
    for thing in responses:
        for item in data:
            if (thing.ticket_id == item["ticket_id"]) and (thing.response_id == item["response_id"]):
                assert thing.response == item["response"]
                assert thing.responder_id == item["responder_id"]
    assert response["status"] == "success"

#post request for ResponseAPI_by_ticket

def test_post_ResponseAPI_by_ticket_unauthorized():
    request = requests.post(url_RTick)
    response=request.json()
    assert request.status_code==200
    assert response['status']=='unsuccessful, missing the authtoken'

def test_post_ResponseAPI_by_ticket_wrong_role():
    header={"secret_authtoken":token_login_manager(), "Content-Type":"application/json"}
    input_dict = { "ticket_id": 1, "response": "Hello, this was a response change!"}
    data = json.dumps(input_dict)
    request=requests.post(url = url_RTick, headers=header, data = data)
    response = request.json()
    assert request.status_code == 404
    assert response['message'] == "You are not authorized to post responses to a ticket."

def test_post_ResponseAPI_by_ticket_missing_ticket_id():
    header={"secret_authtoken":token_login_student(), "Content-Type":"application/json"}
    input_dict = { }
    data = json.dumps(input_dict)
    request=requests.post(url = url_RTick, headers=header, data = data)
    response = request.json()
    assert request.status_code == 403
    assert response['message'] == "Please provide the ticket id!"

def test_post_ResponseAPI_by_ticket_missing_response():
    header={"secret_authtoken":token_login_student(), "Content-Type":"application/json"}
    input_dict = { "ticket_id": 1}
    data = json.dumps(input_dict)
    request=requests.post(url = url_RTick, headers=header, data = data)
    response = request.json()
    assert request.status_code == 403
    assert response['message'] == "Please add your response!"

def test_post_ResponseAPI_by_ticket_ticket_does_not_exist():
    header={"secret_authtoken":token_login_student(), "Content-Type":"application/json"}
    input_dict = { "ticket_id": 999, "response": "Hello, this was a response change!"}
    data = json.dumps(input_dict)
    request=requests.post(url = url_RTick, headers=header, data = data)
    response = request.json()
    assert request.status_code == 404
    assert response['message'] == "This ticket doesn't exist."

def test_post_ResponseAPI_by_ticket_success():
    header={"secret_authtoken":token_login_student(), "Content-Type":"application/json"}
    input_dict = { "ticket_id": 1, "response": "Hello, this was a response change!"}
    data = json.dumps(input_dict)
    request=requests.post(url = url_RTick, headers=header, data = data)
    response = request.json()
    assert request.status_code == 200
    assert response['status'] == "success"

#patch request for ResponseAPI_by_ticket

def test_patch_ResponseAPI_by_ticket_unauthorized():
    request = requests.patch(url_RTick)
    response=request.json()
    assert request.status_code==200
    assert response['status']=='unsuccessful, missing the authtoken'

def test_patch_ResponseAPI_by_ticket_wrong_role():
    header={"secret_authtoken":token_login_manager(), "Content-Type":"application/json"}
    input_dict = { "response_id": 1}
    data = json.dumps(input_dict)
    request=requests.patch(url = url_RTick, headers=header, data = data)
    response = request.json()
    assert request.status_code == 404
    assert response['message'] == "You are not authorized to update any responses."
    
def test_patch_ResponseAPI_by_ticket_missing_response_id():
    header={"secret_authtoken":token_login_student(), "Content-Type":"application/json"}
    input_dict = { }
    data = json.dumps(input_dict)
    request=requests.patch(url = url_RTick, headers=header, data = data)
    response = request.json()
    assert request.status_code == 404
    assert response['message'] == "Please provide the response id"

def test_patch_ResponseAPI_by_ticket_missing_response():
    header={"secret_authtoken":token_login_student(), "Content-Type":"application/json"}
    input_dict = { "response_id": 1}
    data = json.dumps(input_dict)
    request=requests.patch(url = url_RTick, headers=header, data = data)
    response = request.json()
    assert request.status_code == 404
    assert response['message'] == "Since your update response was blank, your earlier response hasn't been altered."

def test_patch_ResponseAPI_by_ticket_wrong_response_id_or_response_not_by_account():
    header={"secret_authtoken":token_login_student(), "Content-Type":"application/json"}
    input_dict = { "response_id": 1, "response": "Hello, this was a response change!"}
    data = json.dumps(input_dict)
    request=requests.patch(url = url_RTick, headers=header, data = data)
    response = request.json()
    assert request.status_code == 404
    assert response['message'] == "Either your response id is wrong, or this account is not the responder of the particular response."

def test_patch_ResponseAPI_by_ticket():
    #Verifies everything except timestamp
    header={"secret_authtoken":token_login_support_agent(), "Content-Type":"application/json"}
    input_dict = { "response_id": 1, "response": "Hello, this was a response change!"}
    data = json.dumps(input_dict)
    request=requests.patch(url = url_RTick, headers=header, data = data)
    response = request.json()
    assert request.status_code == 200
    assert response['status'] == "success"
    input_dict_2 = {"response_id": input_dict["response_id"]}
    data2 = json.dumps(input_dict_2)
    request2 = requests.post(url = url_RTick, data = data2, headers=header)
    response_request2 = request2.json()
    assert request2.status_code == 200
    assert response_request2["status"] == "success"
    assert response_request2["data"]["response_id"] == input_dict["response_id"]
    assert response_request2["data"]["response"] == input_dict["response"]

#delete request for ResponseAPI_by_responseID_delete

def test_delete_ResponseAPI_by_response_id_wrong_role():
    header={"secret_authtoken":token_login_manager(), "Content-Type":"application/json"}
    request=requests.delete(url = url_RDel, headers=header)
    response = request.json()
    assert response["message"] == "You are not authorized to delete responses."
    assert request.status_code == 404

def test_delete_ResponseAPI_by_response_id_wrong_response_id():
    header={"secret_authtoken":token_login_support_agent(), "Content-Type":"application/json"}
    request=requests.delete(url = url_RDel, headers=header)
    response = request.json()
    assert request.status_code == 404
    assert response["message"] == "Either the response you are trying to delete is not yours, or the response doesn't exist in the first place."

#post request for responseAPI by user

def test_post_ResponseAPI_by_user_unauthenticated():
    request=requests.post(url_RUser)
    response=request.json()
    assert request.status_code==200
    assert response['status']=='unsuccessful, missing the authtoken'

def test_post_ResponseAPI_by_user_wrong_role():
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    input_dict = { "responder_id": 2}
    data = json.dumps(input_dict)
    request=requests.post(url = url_RUser, headers=header, data = data)
    response = request.json()
    assert request.status_code == 404
    assert response["message"] == "Sorry, you don't have access to this feature!"

def test_post_ResponseAPI_by_user_missing_responder_id():
    header={"secret_authtoken":token_login_manager(), "Content-Type":"application/json"}
    input_dict = { }
    data = json.dumps(input_dict)
    request=requests.post(url = url_RUser, headers=header, data = data)
    response = request.json()
    assert request.status_code == 403
    assert response["message"] == "Please provide a responder ID for which you need the responses."

def test_post_ResponseAPI_by_user():
    #Checks everything apart from timestamp
    header={"secret_authtoken":token_login_manager(), "Content-Type":"application/json"}
    input_dict = { "responder_id": 2}
    data = json.dumps(input_dict)
    request=requests.post(url = url_RUser, headers=header, data = data)
    response = request.json()
    assert request.status_code == 200
    data = response["data"]
    responses = list(Response.query.filter_by(responder_id = input_dict["responder_id"]).all())
    assert len(data) == len(responses)
    for item in data:
        for thing in responses:
            if thing.response_id == item["response_id"]:
                assert thing.ticket_id == item["ticket_id"]
                assert thing.response == item["response"]
                assert thing.responder_id == item["responder_id"]

#post request for ResponseAPI_by_response_id

def test_post_ResponseAPI_by_response_id_unauthenticated():
    request=requests.post(url_RR)
    response=request.json()
    assert request.status_code==200
    assert response['status']=='unsuccessful, missing the authtoken'

def test_post_ResponseAPI_by_response_id_missing_response_id():
    header={"secret_authtoken":token_login_support_agent(), "Content-Type":"application/json"}
    input_dict = { }
    data = json.dumps(input_dict)
    request=requests.post(url = url_RR, headers=header, data = data)
    response = request.json()
    assert request.status_code == 403
    assert response["message"] == "Please provide a response ID."
    
def test_post_ResponseAPI_by_response_id_wrong_response_id():
    header={"secret_authtoken":token_login_support_agent(), "Content-Type":"application/json"}
    input_dict = {"response_id": 1000 }
    data = json.dumps(input_dict)
    request=requests.post(url = url_RR, headers=header, data = data)
    response = request.json()
    assert request.status_code == 200
    assert response["status"] == "succcess"
    assert response["data"] == []

def test_post_ResponseAPI_by_response_id():
    #Checks all values except timestamp
    header={"secret_authtoken":token_login_support_agent(), "Content-Type":"application/json"}
    input_dict = {"response_id": 1 }
    data = json.dumps(input_dict)
    request=requests.post(url = url_RR, headers=header, data = data)
    response = request.json()
    assert request.status_code == 200
    response_table = Response.query.filter_by(response_id = input_dict["response_id"]).first()
    assert response["data"]["response_id"] == input_dict["response_id"]
    assert response["data"]["ticket_id"] == response_table.ticket_id
    assert response["data"]["response"] == response_table.response
    assert response["data"]["responder_id"] == response_table.responder_id
    
#get request for class TicketAllAPI

def test_ticket_all_get():
    header = {"secret_authtoken":token_login_student()}
    request=requests.get(url_tt_all,headers=header)
    tickets = list(Ticket.query.filter_by().all())
    response = request.json()
    responses = response["data"]
    assert request.status_code==200
    for d in responses:
        for q in tickets:
            if q.ticket_id == d['ticket_id']:
                assert d['ticket_id'] ==  q.ticket_id
                assert d['title']==q.title
                assert d['description']==q.description
                assert d['creation_date']== str(q.creation_date)
                assert d['creator_id']==q.creator_id
                assert d['number_of_upvotes']==q.number_of_upvotes
                assert d['is_read']==q.is_read
                assert d['is_open']==q.is_open
                assert d['is_offensive']== q.is_offensive
                assert d['is_FAQ']==q.is_FAQ
                assert d['rating']==q.rating
    assert len(tickets) == len(responses)
def test_ticket_all_unauthenticated_get():
    request=requests.get(url_tt_all)
    response=request.json()
    assert request.status_code==200
    assert response['status']=='unsuccessful, missing the authtoken'

#patch request for class TicketAllAPI

def test_ticket_all_patch():
    input_dict = { "number_of_upvotes": 146,"is_read": False, "ticket_id": 2}
    data = json.dumps(input_dict)
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.patch(url_tt_all,data=data, headers=header)
    assert request.status_code==200
    assert request.json()['message']=="success"
    ticket = Ticket.query.filter_by(ticket_id=input_dict["ticket_id"]).first()
    assert input_dict["number_of_upvotes"] == ticket.number_of_upvotes
    assert input_dict["is_read"] == ticket.is_read

def test_ticket_all_patch_ticket_not_found():
    input_dict = { "number_of_upvotes": 10023,"is_read": False, "ticket_id": 1e4}
    data = json.dumps(input_dict)
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.patch(url_tt_all,data=data, headers=header)
    assert request.status_code==404
    assert request.json()['message']=="There is no such ticket by that ID"

def test_ticket_all_patch_no_ticket_id():
    input_dict = { "number_of_upvotes": 10023,"is_read": False}
    data = json.dumps(input_dict)
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.patch(url_tt_all,data=data, headers=header)
    assert request.status_code==403
    assert request.json()['message']=="Please mention the ticketId field in your form"


def test_ticket_all_unauthenticated_patch():
    request=requests.patch(url_tt_all)
    response=request.json()
    assert request.status_code==200
    assert response['status']=='unsuccessful, missing the authtoken'


#get request for class getResolutionTimes

def test_getResolutionTimes_post_unauthenticated():
    request=requests.post(url_getResTime)
    response=request.json()
    assert request.status_code==200
    assert response['status']=='unsuccessful, missing the authtoken'

def test_getResolutionTimes_post_wrong_role():
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    input_dict = { "number_of_upvotes": 10023,"is_read": False, "ticket_id": 1e4}
    data = json.dumps(input_dict)
    request=requests.post(url = url_getResTime,data = data, headers=header)
    response = request.json()
    assert request.status_code == 404
    assert response["message"] == "You are not authorized to access this feature!"

def test_getResolutionTimes_post_no_ticket_id():
    header={"secret_authtoken":token_login_manager(), "Content-Type":"application/json"}
    input_dict = {}
    data = json.dumps(input_dict)
    request=requests.post(url = url_getResTime,data = data, headers=header)
    response = request.json()
    assert request.status_code == 403
    assert response["message"] == "Please enter the ticket ID."
    
def test_getResolutionTimes_post_ticket_isopen():
    header={"secret_authtoken":token_login_manager(), "Content-Type":"application/json"}
    input_dict = {"ticket_id": 1}
    data = json.dumps(input_dict)
    request=requests.post(url = url_getResTime,data = data, headers=header)
    response = request.json()
    assert request.status_code == 404
    assert response["message"] == "This ticket hasn't been responded to yet or is still open!"

def test_getResolutionTimes_post_wrong_ticket_id():
    header={"secret_authtoken":token_login_manager(), "Content-Type":"application/json"}
    input_dict = {"ticket_id": 1000}
    data = json.dumps(input_dict)
    request=requests.post(url = url_getResTime,data = data, headers=header)
    response = request.json()
    assert request.status_code == 404
    assert response["message"] == "No such ticket exists by the given ticket ID."

def test_getResolutionTimes_post():
    #Only checks if days, seconds, microseconds and ticket IDs match
    header={"secret_authtoken":token_login_manager(), "Content-Type":"application/json"}
    input_dict = {"ticket_id": [1,2]} 
    data = json.dumps(input_dict)
    request=requests.post(url = url_getResTime,data = data, headers=header)
    response = request.json()
    assert request.status_code == 200
    if isinstance(input_dict["ticket_id"], int):
        responses = Response.query.filter_by(ticket_id = input_dict["ticket_id"]).all()
        responses = list(responses)
        ticket = Ticket.query.filter_by(ticket_id = input_dict["ticket_id"]).first()
        a = {}
        response_times = []
        for thing in responses:
            if isinstance(thing.response_timestamp, datetime):
                #print("Here 1")
                response_times.append(thing.response_timestamp)
            elif isinstance(thing.response_timestamp, str):
                #print("Here 2")
                response_times.append(datetime.strptime(thing.response_timestamp,'%Y-%m-%d %H:%M:%S.%f'))
            response_time = max(response_times)
            a["creation_time"] = None
            if isinstance(ticket.creation_date, str):
                a["creation_time"] = datetime.strptime(ticket.creation_date, '%Y-%m-%d %H:%M:%S.%f')
            elif isinstance(ticket.creation_date, datetime):
                a["creation_time"] = ticket.creation_date
            a["response_time"] = response_time
            a["resolution_time_datetime_format"] = a["response_time"] - a["creation_time"]
            a["days"] = a["resolution_time_datetime_format"].days
            a["seconds"] = a["resolution_time_datetime_format"].seconds
            a["microseconds"] = a["resolution_time_datetime_format"].microseconds
            a["resolution_time_datetime_format"] = str(a["resolution_time_datetime_format"])
            a["creation_time"] = a["creation_time"]
            a["ticket_id"] = input_dict["ticket_id"]
            a["response_time"] = None
            a["resolution_time_datetime_format"] = None
            a["creation_time"] = None
        d = response["data"]
        for keys in a:
            if a[keys] is not None:
                assert a[keys] == d[keys]
    elif isinstance(input_dict["ticket_id"], list):
        data = []        
        for item in input_dict["ticket_id"]:
            d = {}
            ticket = None
            ticket = Ticket.query.filter_by(ticket_id = item).first()
            if ticket is None:
                continue
            if isinstance(ticket.creation_date, str):
                d["creation_time"] = datetime.strptime(ticket.creation_date, '%Y-%m-%d %H:%M:%S.%f')
            elif isinstance(ticket.creation_date, datetime):
                d["creation_time"] = ticket.creation_date
            responses = Response.query.filter_by(ticket_id = item).all()
            if ticket.is_open == False:
                responses = list(responses)
                response_times = []
                for thing in responses:
                    if isinstance(thing.response_timestamp, datetime):
                        response_times.append(thing.response_timestamp)
                    elif isinstance(thing.response_timestamp, str):
                        #print("Here 2")
                        response_times.append(datetime.strptime(thing.response_timestamp,'%Y-%m-%d %H:%M:%S.%f'))
                    
                response_time = max(response_times)
                d["response_time"] = response_time
                d["resolution_time_datetime_format"] = d["response_time"] - d["creation_time"]
                d["days"] = d["resolution_time_datetime_format"].days
                d["seconds"] = d["resolution_time_datetime_format"].seconds
                d["microseconds"] = d["resolution_time_datetime_format"].microseconds
                d["response_time"] = d["response_time"]
                d["resolution_time_datetime_format"] = str(d["resolution_time_datetime_format"])
                d["creation_time"] = d["creation_time"]
                d["ticket_id"] = item
                d["response_time"] = None
                d["resolution_time_datetime_format"] = None
                d["creation_time"] = None
                data.append(d)
        x = response["data"]
        for item in x:
            for thing in data:
                if item["ticket_id"] == thing["ticket_id"]:
                    for keys in thing:
                        if thing[keys] is not None:
                            assert thing[keys] == item[keys]

#get request for class flaggedPostAPI

def test_get_flaggedPost_wrong_role():
    header={"secret_authtoken":token_login_support_agent(), "Content-Type":"application/json"}
    request=requests.get(url = url_flagPost, headers=header)
    response = request.json()
    assert request.status_code == 404
    assert response["message"] == "You are not authorized to access this feature."

def test_get_flaggedPost():
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    request=requests.get(url = url_flagPost, headers=header)
    response = request.json()
    assert request.status_code == 200
    flagged_posts = list(url_flagPost.query.filter_by().all())
    d = response["data"]
    assert len(flagged_posts) == len(d)
    for item in flagged_posts:
        for thing in d:
            if item.ticket_id == thing["ticket_id"]:
                assert item.flagger_id == thing["flagger_id"]
                assert item.creator_id == thing["creator_id"]

def test_get_flaggedPost_unauthenticated():
    request=requests.get(url_flagPost)
    response=request.json()
    assert request.status_code==200
    assert response['status']=='unsuccessful, missing the authtoken'

#post request for class flaggedPostAPI

def test_post_flaggedPost_wrong_role():
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    input_dict = { "ticket_id": 1,"flagger_id": 2, "creator_id": 1}
    data = json.dumps(input_dict)
    request=requests.post(url = url_flagPost, headers=header, data = data)
    response = request.json()
    assert request.status_code == 404
    assert response["message"] == "You are not authorized to access this feature."

def test_post_flaggedPost_unauthenticated():
    request=requests.post(url_flagPost)
    response=request.json()
    assert request.status_code==200
    assert response['status']=='unsuccessful, missing the authtoken'

def test_post_flaggedPost_missing_flagger_id():
    header={"secret_authtoken":token_login_support_agent(), "Content-Type":"application/json"}
    input_dict = { "ticket_id": 1, "creator_id": 1}
    data = json.dumps(input_dict)
    request=requests.post(url = url_flagPost, headers=header, data = data)
    response = request.json()
    assert request.status_code == 403
    assert response["message"] == "Please pass the flagger ID."

def test_post_flaggedPost_missing_creator_id():
    header={"secret_authtoken":token_login_support_agent(), "Content-Type":"application/json"}
    input_dict = { "ticket_id": 1,"flagger_id": 2 }
    data = json.dumps(input_dict)
    request=requests.post(url = url_flagPost, headers=header, data = data)
    response = request.json()
    assert request.status_code == 403
    assert response["message"] == "Please pass the creator ID."

def test_post_flaggedPost_missing_ticket_id():
    header={"secret_authtoken":token_login_support_agent(), "Content-Type":"application/json"}
    input_dict = { "creator_id": 1,"flagger_id": 2 }
    data = json.dumps(input_dict)
    request=requests.post(url = url_flagPost, headers=header, data = data)
    response = request.json()
    assert request.status_code == 403
    assert response["message"] == "Please pass the Ticket ID."

def test_post_flaggedPost_wrong_flagger_id():
    header={"secret_authtoken":token_login_support_agent(), "Content-Type":"application/json"}
    input_dict = { "ticket_id": 1, "creator_id": 1,"flagger_id": 100 }
    data = json.dumps(input_dict)
    request=requests.post(url = url_flagPost, headers=header, data = data)
    response = request.json()
    assert request.status_code == 403
    assert response["message"] == "The person who flagged must be a support agent."

def test_post_flaggedPost_wrong_creator_id():
    header={"secret_authtoken":token_login_support_agent(), "Content-Type":"application/json"}
    input_dict = { "ticket_id": 1, "creator_id": 100,"flagger_id": 2 }
    data = json.dumps(input_dict)
    request=requests.post(url = url_flagPost, headers=header, data = data)
    response = request.json()
    assert request.status_code == 403
    assert response["message"] == "The person who created the post must be a student."

def test_post_flaggedPost_wrong_ticket_id():
    header={"secret_authtoken":token_login_support_agent(), "Content-Type":"application/json"}
    input_dict = { "ticket_id": 1000, "creator_id": 1,"flagger_id": 2 }
    data = json.dumps(input_dict)
    request=requests.post(url = url_flagPost, headers=header, data = data)
    response = request.json()
    assert request.status_code == 403
    assert response["message"] == "The referenced ticket is not created by the referenced person/ the ticket doesn't exist in the first place."

#patch request for class flaggedPostAPI

def test_patch_flaggedPost_wrong_role():
    header={"secret_authtoken":token_login_support_agent(), "Content-Type":"application/json"}
    input_dict = { "ticket_id": 1, "is_approved": True}
    data = json.dumps(input_dict)
    request=requests.patch(url = url_flagPost, headers=header, data = data)
    response = request.json()
    assert request.status_code == 404
    assert response["message"] == "You are not authorized to access this feature."

def test_patch_flaggedPost_unauthenticated():
    request=requests.patch(url_flagPost)
    response=request.json()
    assert request.status_code==200
    assert response['status']=='unsuccessful, missing the authtoken'

def test_patch_flaggedPost_missing_ticket_id():
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    input_dict = { "is_approved": True}
    data = json.dumps(input_dict)
    request=requests.patch(url = url_flagPost, headers=header, data = data)
    response = request.json()
    assert request.status_code == 403
    assert response["message"] == "Please provide the ticket id"

def test_patch_flaggedPost_missing_approval():
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    input_dict = { "ticket_id": 1}
    data = json.dumps(input_dict)
    request=requests.patch(url = url_flagPost, headers=header, data = data)
    response = request.json()
    assert request.status_code == 403
    assert response["message"] == "Please provide either approval or rejection"

def test_patch_flaggedPost_success_approval():
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    input_dict = { "ticket_id": 1, "is_approved": True}
    data = json.dumps(input_dict)
    request=requests.patch(url = url_flagPost, headers=header, data = data)
    response = request.json()
    assert request.status_code == 200
    assert response["status"] == "success"

def test_patch_flaggedPost_success_rejection():
    header={"secret_authtoken":token_login_admin(), "Content-Type":"application/json"}
    input_dict = { "ticket_id": 1, "is_rejected": True}
    data = json.dumps(input_dict)
    request=requests.patch(url = url_flagPost, headers=header, data = data)
    response = request.json()
    assert request.status_code == 200
    assert response["status"] == "success"

#post request for class ImportResourceUser

def test_post_ImportResourceUser_unauthorized():
    # Test unauthorized access
    response = requests.post(url = url_ImportResourceUser)
    assert response.status_code == 401

def test_post_ImportResourceUser_invalid_file():
    # Test uploading a file without the required format
    files = {'file': open('invalid_file.txt', 'rb')}
    response = requests.post(url = url_ImportResourceUser, files=files)
    assert response.status_code == 400

def test_post_ImportResourceUser_unauthorized_user():
    # Test unauthorized user trying to access the feature
    files = {'file': open('valid_users.csv', 'rb')}
    headers = {"Authorization": "Bearer invalid_token"}
    response = requests.post(url = url_ImportResourceUser, headers=headers, files=files)
    assert response.status_code == 401

def test_post_ImportResourceUser_success():
    # Test uploading a valid file by an authorized user
    files = {'file': open('valid_users.csv', 'rb')}
    headers = {"Authorization": "Bearer valid_token"}
    response = requests.post(url = url_ImportResourceUser, headers=headers, files=files)
    assert response.status_code == 200
    assert "message" in response.json()
    assert response.json()["message"] == "File uploaded successfully"

#post request for Category_API

def test_get_CategoryAPI_unauthorized():
    # Test unauthorized access
    request = requests.get(url = url_Category)
    response = request.json()
    assert request.status_code == 200
    assert response['status'] == 'unsuccessful, missing the authtoken'

def test_get_CategoryAPI_success():
    # Test getting categories successfully
    header = {"secret_authtoken": token_login_admin(), "Content-Type": "application/json"}
    request = requests.get(url = url_Category, headers=header)
    response = request.json()
    assert request.status_code == 200
    assert "data" in response
    assert isinstance(response["data"], list)

def test_get_CategoryAPI_no_categories():
    # Test getting categories when no categories exist
    header = {"secret_authtoken": token_login_admin(), "Content-Type": "application/json"}
    # Assuming no categories exist by using an empty database or removing all categories
    request = requests.get(url = url_Category, headers=header)
    response = request.json()
    assert request.status_code == 200
    assert "data" in response
    assert isinstance(response["data"], list)
    assert len(response["data"]) == 0

#post request for Category_API

def test_post_CategoryAPI_unauthorized():
    # Test unauthorized access
    request = requests.post(url = url_Category)
    response = request.json()
    assert request.status_code == 200
    assert response['status'] == 'unsuccessful, missing the authtoken'

def test_post_CategoryAPI_wrong_role():
    # Test wrong role
    header = {"secret_authtoken": token_login_manager(), "Content-Type": "application/json"}
    input_dict = {"category": "Test Category"}
    data = json.dumps(input_dict)
    request = requests.post(url = url_Category, headers=header, data=data)
    response = request.json()
    assert request.status_code == 404
    assert response['message'] == "You are not authorized to post categories."

def test_post_CategoryAPI_missing_category():
    # Test missing category parameter
    header = {"secret_authtoken": token_login_support_agent(), "Content-Type": "application/json"}
    data = json.dumps({})
    request = requests.post(url = url_Category, headers=header, data=data)
    response = request.json()
    assert request.status_code == 400
    assert response['message'] == "category is required and should be string"

def test_post_CategoryAPI_success():
    # Test adding a new category
    header = {"secret_authtoken": token_login_admin(), "Content-Type": "application/json"}
    input_dict = {"category": "Test Category"}
    data = json.dumps(input_dict)
    request = requests.post(url = url_Category, headers=header, data=data)
    response = request.json()
    assert request.status_code == 200
    assert response['status'] == "success"





