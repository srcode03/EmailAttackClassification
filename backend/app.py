# Module Imports
import mariadb
import sys
import email 
import re
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS, cross_origin
import numpy as np
import pickle
from feature import FeatureExtraction

with open('emailmodel.pkl', 'rb') as f:
    clf = pickle.load(f)

with open('phishingmodel.pkl', 'rb') as f:
    gbc = pickle.load(f)

app = Flask(__name__)
CORS(app, support_credentials=True)

# Connect to MariaDB Platform
try:
    conn = mariadb.connect(
        user="root",
        password="",
        host="localhost",
        port=3310,
        database="emails"
    )
    print(f"Connected to MariaDB Database successfully")
except mariadb.Error as e:
    print(f"Error connecting to MariaDB Platform: {e}")
    sys.exit(1)

# Get Cursor
cur = conn.cursor()

def predictEmail(emails):
    predictions = clf.predict(emails)
    return list(predictions)

@app.route('/email', methods=['POST', 'GET'])
def process_email():
    data = request.get_json()
    content = []
    content.insert(0, data['content'])
    print(content)
    prediction = predictEmail(content)
    print(prediction)
    email_id = data['emailId']
    cur = conn.cursor()
    cur.execute(
        "SELECT email_id FROM email where email_id = %s", (email_id,))
    senderData = cur.fetchone()
    if senderData is None:
        cur.execute(
            "INSERT INTO email (email_id) VALUES (%s)", (email_id,))
    cur.execute(
        "SELECT email_id, no_of_reports FROM email where email_id = %s", (email_id,))
    senderData = cur.fetchone()
    email_id, no_of_reports = senderData
    if prediction[0] == 1:
        if no_of_reports is None:
            no_of_reports = 1
        else:
            no_of_reports += 1
        print(no_of_reports)
    update_query = "UPDATE email SET no_of_reports=%s WHERE email_id=%s"
    cur.execute(update_query, (no_of_reports, email_id,))
    conn.commit()
    response = {
        "isSpam": int(prediction[0]),
        "no_of_reports": no_of_reports,
    }
    response = jsonify(response)
    response.headers.add("Access-Control-Allow-Origin", "*")
    cur.close()
    return response

@app.route("/phishing", methods=["POST"])
def check_phishing():
    if request.method == "POST":
        data = request.get_json()
        url = data['url']
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)

        y_pred = gbc.predict(x)[0]
        # 1 is safe, -1 is unsafe
        y_pro_phishing = gbc.predict_proba(x)[0, 0]
        y_pro_non_phishing = gbc.predict_proba(x)[0, 1]
        # if(y_pred ==1 ):
        pred = "It is {0:.2f} % safe to go ".format(y_pro_phishing*100)
        return jsonify({"result": pred})

@app.route("/header", methods=["POST"])
def analyze_email_header():
    try:
        data = request.get_json()
        email_content = data.get("emailContent", "")
        msg = email.message_from_string(email_content)

        # Check for common signs of phishing attacks
        if 'Received' not in msg:
            return jsonify({"result": "Suspicious: No 'Received' header found"})

        if 'DKIM-Signature' not in msg:
            return jsonify({"result": "Warning: No DKIM signature found"})

        if 'Return-Path' not in msg:
            return jsonify({"result": "Suspicious: No 'Return-Path' found"})

        # Check for known phishing indicators
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/html':
                    return jsonify({"result": "Warning: HTML content detected"})

        # Check for suspicious links in the body
        links = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', str(msg))
        if links:
            return jsonify({"result": f"Warning: Suspicious links found: {', '.join(links)}"})

        # Check for spoofed sender (compare 'From' and 'Return-Path')
        from_address = msg.get('From', '').strip()
        return_path = msg.get('Return-Path', '').strip('<>')
        if from_address and return_path and from_address != return_path:
            return jsonify({"result": "Warning: Sender spoofing detected"})

        # Add more checks based on your specific needs

        # If no suspicious signs found, return a safe message
        return jsonify({"result": "No suspicious signs detected"})
    except Exception as e:
        return jsonify({"error": str(e)})

# Ensure that you're using the correct method name (not conflicting with the imported 'email' module)
if __name__ == '__main__':
    app.run(debug=True)
