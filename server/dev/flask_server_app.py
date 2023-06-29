import sys
import os
import json
import re
from flask import Flask, render_template, request, jsonify, redirect, url_for

CURDIR = os.path.dirname(os.path.abspath(__file__))
CONF_FILE = CURDIR+"/configuration/config.json"
STATIC_PATH = CURDIR+"/static"
TEMPLATE_PATH = CURDIR+"/templates"

#redirecting stdout and stderr to null, to avoid output
sys.stdout = open(os.devnull, 'w')
sys.stderr = open(os.devnull, 'w')

app = Flask(__name__)

with open(CONF_FILE, 'r') as f:
    data = json.load(f)
     
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

#validating email format
@app.route('/validate_email', methods=['POST'])
def validate_email():
    email = request.form.get('email')
    if email in data['admins']:
        return jsonify({'valid': False, 'message': 'User already exists'})
    elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'valid': False, 'message': 'Invalid email address'})
    else:
        #reaching this means the input isnt an existing email and matches the format, so its valid
        return jsonify({'valid': True})

#validating email to be removed (checks if it exists)
@app.route('/validate_email_removal', methods=['POST'])
def validate_email_removal():
    email = request.form.get('email')
    if email not in data['admins']:
        return jsonify({'valid': False, 'message': 'User not found'})
    else:
        return jsonify({'valid': True})

#registration
@app.route('/register', methods=['POST', 'GET'])
def register():
    #registering the email
    if request.method == 'POST':
        email = request.form.get('email')
        if email in data['admins']:
            return 'User already exists'
        else:
            data['admins'].append(email)
            with open(CONF_FILE, 'w') as f:
                json.dump(data, f) #updating the config file with the updated admin list
            return redirect(url_for('success'))
    else:
        return render_template('register.html')

#registration success page
@app.route('/success', methods=['GET'])
def success():
    company_hash = data['company_hash']
    return render_template('success.html', key=company_hash)

#removing user
@app.route('/remove', methods=['GET', 'POST'])
def remove():
    if request.method == 'POST':
        email = request.form.get('email')
        if email in data['admins']:
            data['admins'].remove(email)
            with open(CONF_FILE, 'w') as f:
                json.dump(data, f) 
        else:
            return 'User not found'
    return render_template('remove.html')

if __name__=="__main__":
    app.run(host="localhost", port=5000, debug=False)