#importing required libraries
import numpy as np
import pandas as pd
from sklearn import metrics 
data = pd.read_csv(r"C:\Users\Shaunak\Desktop\EmailAttackClassification\flask-backend\phishing.csv")
# Splitting the dataset into dependant and independant fetature
data = data.drop(['Index'],axis = 1)
X = data.drop(["class"],axis =1)
y = data["class"]
# Splitting the dataset into train and test sets: 80-20 split

from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, random_state = 42)
X_train.shape, y_train.shape, X_test.shape, y_test.shape  
print("X_test shape:", X_test.shape)  
from xgboost import XGBClassifier

# instantiate the model
gbc = GradientBoostingClassifier(max_depth=4,learning_rate=0.7)

# fit the model 
gbc.fit(X_train,y_train)
import pickle

# dump information to that file
filename = "phishingmodel.pkl"
with open(filename, 'wb') as f:
    pickle.dump(gbc, f)