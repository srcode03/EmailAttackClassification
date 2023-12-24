import pickle
import sklearn
from sklearn.pipeline import Pipeline
from sklearn.naive_bayes import MultinomialNB
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
import pandas as pd
data = pd.read_csv("spam.csv", encoding="ISO-8859-1")
data.isna().sum()
data['Spam'] = data['v1'].apply(lambda x: 1 if x == 'spam' else 0)
data.head(5)
X_train, X_test, y_train, y_test = train_test_split(
    data.v2, data.Spam, test_size=0.25)
# CounterVectorizer Convert the text into matrics
clf = Pipeline([
    ('vectorizer', CountVectorizer()),
    ('nb', MultinomialNB())
])
clf.fit(X_train, y_train)
emails = [
    'Sounds great! Are you home now?',
    'Will u meet ur dream partner soon? Is ur career off 2 a flyng start? 2 find out free, txt HORO followed by ur star sign, e. g. HORO ARIES'
]
print(clf.predict(emails))
print(clf.score(X_test, y_test))
filename = "emailmodel.pkl"
with open(filename, 'wb') as f:
    pickle.dump(clf, f)
