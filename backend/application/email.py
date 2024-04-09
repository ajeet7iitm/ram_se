# from flask import Flask
# from flask_mail import Mail
# from flask import request, url_for
# from flask_mail import Message
# import secrets

# app = Flask(__name__)
# app.config['MAIL_SERVER'] = 'mailhog'
# app.config['MAIL_PORT'] = 1025  # MailHog SMTP port
# app.config['MAIL_USE_TLS'] = False
# app.config['MAIL_USE_SSL'] = False
# app.config['MAIL_USERNAME'] = None
# app.config['MAIL_PASSWORD'] = None

# mail = Mail(app)
def send_verification_email(email, verification_token):
    return 1
# def send_verification_email(email, verification_token):
#     #verification_link = url_for('verify_email', token=verification_token, _external=True)
#     verification_link="xyz"
#     msg = Message('Email Verification', sender='your@email.com', recipients=[email])
#     msg.body = f'Click the following link to verify your email: {verification_link}'
#     mail.send(msg)
from flask import Flask
from flask_mail import Mail
from flask_mail import Message

app = Flask(__name__)
mail = Mail(app)

app.config['MAIL_SERVER'] = 'docker_dev/mailhog'
app.config['MAIL_PORT'] =  1025
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = None
app.config['MAIL_PASSWORD'] = None
app.config['MAIL_SENDER'] = 'sender@example.com'  # Set the default sender

app.config['MAIL_SENDMAIL_PATH'] = '/usr/local/bin/mhsendmail'


def send_email():
    msg = Message('Hello from Flask', sender='sender@example.com', recipients=['recipient@example.com'])
    msg.body = 'This is a test email sent from Flask to MailHog in Docker.'
    mail.send(msg)
    return 'Email sent!'


