from flask import current_app as app
from flask_mail import Mail, Message

# Flask app configuration for MailHog
# http://localhost:8025/
app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 1025
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = "me@example.com"
mail = Mail(app)
app.app_context().push()
users=["sachii@gmail.com", "rahul@gmail.com", "rohan@gmail.com"]

def index():
    with mail.connect() as conn:
        for user in users:
            message = '...'
            subject = "hello" 
            msg = Message(recipients=[user],html='<b>testing</b>',subject=subject)
            with app.open_resource("image.png") as fp:
                msg.attach("image.png", "image/png", fp.read())
            conn.send(msg)
    return "Sent successfully"