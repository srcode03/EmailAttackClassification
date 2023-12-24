# Module Imports
import mariadb
import sys
from flask import Flask, request,jsonify,render_template
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
    print(f"Connected to MariaDB Database sucessfully")
except mariadb.Error as e:
    print(f"Error connecting to MariaDB Platform: {e}")
    sys.exit(1)
# Get Cursor
cur = conn.cursor()
def predictEmail(emails):
    predictions = clf.predict(emails)
    return list(predictions)
@app.route('/email', methods=['POST', 'GET'])
def email():
    data = request.get_json()
    content = []
    content.insert(0,data['content'])
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
        if no_of_reports==None:
            no_of_reports =1
        else:
            no_of_reports+=1
        print(no_of_reports)
    update_query = "UPDATE email SET no_of_reports=%s WHERE email_id=%s"
    cur.execute(update_query, (no_of_reports,email_id,))
    conn.commit()
    response = {
        "isSpam": int(prediction[0]),
        "no_of_reports": no_of_reports,
    }
    response = jsonify(response)
    response.headers.add("Access-Control-Allow-Origin", "*")
    cur.close()
    return (response)
@app.route("/phishing", methods=["GET", "POST"])
def phishing():
    if request.method == "POST":
        data = request.get_json()
        url = data['url']
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1,30) 

        y_pred =gbc.predict(x)[0]
        #1 is safe       
        #-1 is unsafe
        y_pro_phishing = gbc.predict_proba(x)[0,0]
        y_pro_non_phishing = gbc.predict_proba(x)[0,1]
        # if(y_pred ==1 ):
        pred = "It is {0:.2f} % safe to go ".format(y_pro_phishing*100)
        return jsonify(pred)
if __name__ == '__main__':
    app.run(debug=True)
