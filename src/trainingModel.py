import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

dataset = pd.read_csv('data/phishing.csv')

# print(dataset['class'].value_counts()) # Checks how many links are phishing and how many are not

x_data = dataset[['UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//',
       'PrefixSuffix-', 'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon',
       'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL',
       'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail', 'AbnormalURL',
       'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
       'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
       'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage',
       'StatsReport']]

y_data = dataset[['class']]


x_train, x_test, y_train, y_test = train_test_split(x_data, y_data, test_size=0.2, random_state=42) #Splits the dataset into training and testing sets
model = RandomForestClassifier(random_state=42)
model.fit(x_train, y_train.values.ravel())  # Fits the model to the training data, uses ravel() to get rid of DataConversionWarning (1d array was expected)

y_pred = model.predict(x_test)  # Makes predictions on the test data
accuracy = accuracy_score(y_test, y_pred)  # Calculates the accuracy of the model
print(f'Accuracy: {accuracy}')  # Prints the accuracy of the model
print(classification_report(y_test, y_pred))  # Prints a detailed classification report