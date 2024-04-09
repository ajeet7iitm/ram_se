from application import app, api, celery, api2
from application.routes import *

from application.api import TicketAPI , UserAPI, FAQApi, ResponseAPI_by_response_id
from application.api import ResponseAPI_by_ticket, ResponseAPI_by_user,TicketAll, CategoryAPI
from application.api import getResolutionTimes, flaggedPostAPI, getResponseAPI_by_ticket
from application.api import TicketDelete,UserDelete,ImportResourceUser, ResponseAPI_by_responseID_delete

from application.api2 import Sitaram, Discourse_post, Registration, Verification
from application.api3 import Login
from application.discourseapi import Category, Topic, Notifications


#discourse apis from ajeet
api.add_resource(Verification, '/api/discourse/self_account/activate')
api.add_resource(Registration, '/api/discourse/register')
api.add_resource(Sitaram, '/api/discourse/sitaram_user')
api.add_resource(Discourse_post, '/api/discourse/sitaram_post1')
########################################################
##geogre APIs
api.add_resource(Category, '/api/discourse/category')
api.add_resource(Topic, '/api/discourse/topic')
api.add_resource(Notifications, '/api/discourse/notifications')

#application apis
api.add_resource(TicketAPI, '/api/ticket')
api.add_resource(UserAPI,'/api/user')
api.add_resource(FAQApi, '/api/faq', '/api/faq/<int:ticket_id>')
api.add_resource(ResponseAPI_by_ticket, '/api/respTicket') #For getting responses with ticket_id
api.add_resource(ResponseAPI_by_response_id, '/api/respResp') #For getting responses with response_id
api.add_resource(ResponseAPI_by_user, '/api/respUser') #For getting responses with user id.
api.add_resource(TicketAll, '/api/ticketAll') #For getting all tickets
api.add_resource(getResolutionTimes, '/api/getResolutionTimes') # For getting resolution times of support agents, only accessible to managers.
api.add_resource(flaggedPostAPI, '/api/flaggedPosts') #For getting the flagged posts.
api.add_resource(getResponseAPI_by_ticket,'/api/getResponseAPI_by_ticket') #Only for getting the responses by ticket ID
api.add_resource(Login,'/login')
api.add_resource(ImportResourceUser,'/api/importUsers')
api.add_resource(TicketDelete,'/api/ticket/<int:ticket_id>')
api.add_resource(UserDelete,'/api/user/<int:user_id>') 
api.add_resource(ResponseAPI_by_responseID_delete, '/api/respRespDel/<int:responder_id>/<int:response_id>')
api.add_resource(CategoryAPI, '/api/category')


if __name__ == '__main__':
  # Run the Flask app
  app.run(debug=True)