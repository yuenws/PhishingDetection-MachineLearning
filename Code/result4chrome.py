import joblib
import featextract4chrome
import sys
import numpy as np

from featextract4chrome import LOCALHOST_PATH, DIRECTORY_NAME


def get_prediction_from_url(test_url):
    features_test = featextract4chrome.main(test_url)
    
    features_test = np.array(features_test).reshape((1, -1))

    clf = joblib.load(LOCALHOST_PATH + DIRECTORY_NAME + '/classifier/DecisionTreeClassifier.pkl')

    pred = clf.predict(features_test)
    return int(pred[0])


def main():
    url = sys.argv[1]

    prediction = get_prediction_from_url(url)

    if prediction == 1:
        print ("The website is safe to browse")

    elif prediction == 0:
        print ("The website has phishing features. DO NOT VISIT!")
 


if __name__ == "__main__":
    main()