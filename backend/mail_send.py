from flask import Flask
from flask_mail import Mail, Message

app = Flask(__name__)
mail = Mail(app)

# Configure Flask-Mail to use MailHog
app.config['MAIL_SERVER'] = 'localhost'  # Assuming 'docker_dev' is the Docker network alias for MailHog
app.config['MAIL_PORT'] = 1025
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = None
app.config['MAIL_PASSWORD'] = None
app.config['MAIL_SENDER'] = 'sender@example.com'
#app.config['MAIL_SENDMAIL_PATH'] = '/usr/local/bin/mhsendmail'

def send_email():
    print(f"Attempting to connect to SMTP server: {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']}")
    msg = Message('Hello from Flask', sender='sender@example.com', recipients=['recipient@example.com'])
    msg.body = 'This is a test email sent from Flask to MailHog in Docker.'
    try:
        with app.app_context():
            mail.send(msg)
    except Exception as e:
        print(f"Failed to send email: {e}")
        return 'Failed to send email!'
    return 'Email sent!'

# def send_email():
#     msg = Message('Hello from Flask', sender='sender@example.com', recipients=['recipient@example.com'])
#     msg.body = 'This is a test email sent from Flask to MailHog in Docker.'
#     mail.send(msg)
#     return 'Email sent!'
@app.route('/')
def ram():
    return "sitaram mahadev"
@app.route('/send1')
def ram1():
    return send_email()

if __name__ == '__main__':
    app.run(debug=True)
