import requests
from flask import json
import sys
import os 
from datetime import datetime
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
# Import necessary models from application
from application.models import Ticket, Response, Flagged_Post

# Add the directory containing the models to the system path
SCRIPT_DIRP = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIRP))

# Base URL for API requests
BASE = "http://127.0.0.1:5000"

# Define URLs for different API endpoints
url_ticket_all = BASE + "/api/ticketAll" 
url_getResolutionTimes = BASE + "/api/getResolutionTimes"
url_flaggedPosts = BASE + "/api/flaggedPosts"
url_respResp = BASE + "/api/respResp"
url_respUser = BASE + "/api/respUser"
url_getRespTicket = BASE + "/api/getResponseAPI_by_ticket"
url_RespTicket = BASE + "/api/respTicket"
url_RespDelete = BASE + "/api/respRespDel/2/8"
url_RespDelete2 = BASE + "/api/respRespDel/2/13"

# Define functions to generate auth tokens for different user roles
def token_login_student():
    url = BASE + "/login"
    data = {"email": "redding.abba@dollstore.org", "password": "arya"}
    response = requests.post(url, data=data)
    return response.json()["token"]

def token_login_support_agent():
    url = BASE + "/login"
    data = {"email": "chirag@chirag.com", "password": "chirag"}
    response = requests.post(url, data=data)
    return response.json()["token"]

def token_login_admin():
    url = BASE + "/login"
    data = {"email": "varun@varun.com", "password": "varun"}
    response = requests.post(url, data=data)
    return response.json()["token"]

def token_login_manager():
    url = BASE + "/login"
    data = {"email": "boss@boss.com", "password": "boss"}
    response = requests.post(url, data=data)
    return response.json()["token"]

# Test case for GET request to retrieve all tickets
def test_ticket_all_get():
    header = {"secret_authtoken": token_login_student()}
    request = requests.get(url_ticket_all, headers=header)
    assert request.status_code == 200
    response_data = request.json()["data"]
    # Add assertions to check response data against database records

# Test case for unauthenticated GET request to retrieve all tickets
def test_ticket_all_unauthenticated_get():
    request = requests.get(url_ticket_all)
    assert request.status_code == 401  # Unauthorized

# Test case for PATCH request to update ticket details
def test_ticket_all_patch():
    input_data = {"number_of_upvotes": 146, "is_read": False, "ticket_id": 2}
    data = json.dumps(input_data)
    header = {"secret_authtoken": token_login_admin(), "Content-Type": "application/json"}
    request = requests.patch(url_ticket_all, data=data, headers=header)
    assert request.status_code == 200
    assert request.json()['message'] == "success"
    # Add assertions to verify that ticket details are updated correctly in the database

# Test case for PATCH request to update ticket details when ticket ID is not found
def test_ticket_all_patch_ticket_not_found():
    input_data = {"number_of_upvotes": 10023, "is_read": False, "ticket_id": 1e4}
    data = json.dumps(input_data)
    header = {"secret_authtoken": token_login_admin(), "Content-Type": "application/json"}
    request = requests.patch(url_ticket_all, data=data, headers=header)
    assert request.status_code == 404
    assert request.json()['message'] == "There is no such ticket by that ID"
    # Add more assertions if needed

# Test case for PATCH request to update ticket details without providing ticket ID
def test_ticket_all_patch_no_ticket_id():
    input_data = {"number_of_upvotes": 10023, "is_read": False}
    data = json.dumps(input_data)
    header = {"secret_authtoken": token_login_admin(), "Content-Type": "application/json"}
    request = requests.patch(url_ticket_all, data=data, headers=header)
    assert request.status_code == 403
    assert request.json()['message'] == "Please mention the ticketId field in your form"
    # Add more assertions if needed

# Test case for unauthenticated PATCH request to update ticket details
def test_ticket_all_unauthenticated_patch():
    request = requests.patch(url_ticket_all)
    assert request.status_code == 401  # Unauthorized

# Similarly, rewrite other test cases following the same pattern
