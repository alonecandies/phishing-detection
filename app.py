#!/usr/bin/env python
"""
This is the Flask REST API that processes and outputs the prediction on the URL.
"""
import numpy as np
import pickle
from flask import Flask, redirect, url_for, render_template, request, jsonify
import json
import pickle
import time
from sklearn.ensemble import RandomForestClassifier
import os
from url_extractor import url_extractor, is_URL_accessible
from concurrent.futures import ThreadPoolExecutor
from pymongo import MongoClient
import tldextract
client = MongoClient("mongodb://localhost:27017")
db = client["phishing"]
blackList = db["blacklist"]
whitelist = db["whitelist"]
dataset = db["dataset_phishing"]

app = Flask(__name__)
app.config["CACHE_TYPE"] = "null"

model = None
with open('./checkpointModel/model_phishing_webpage_classifer', 'rb') as file:
    model = pickle.load(file)

mappingCriteria = ['length_url',
                   'length_hostname',
                   'ip',
                   'nb_dots',
                   'nb_qm',
                   'nb_eq',
                   'nb_slash',
                   'nb_www',
                   'ratio_digits_url',
                   'ratio_digits_host',
                   'tld_in_subdomain',
                   'prefix_suffix',
                   'shortest_word_host',
                   'longest_words_raw',
                   'longest_word_path',
                   'phish_hints',
                   'nb_hyperlinks',
                   'ratio_intHyperlinks',
                   'empty_title',
                   'domain_in_title',
                   'page_rank']

@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    from datetime import datetime

    today = datetime.utcfromtimestamp(
        int(time.time())).strftime('%Y-%m-%d %H:%M:%S')
    if request.method == "POST":
        incoming = request.get_json()
        data = {
            "date": today,
            "url": incoming['url'],
            "content": incoming['content'],
            "type": incoming['type']
        }

        db["feedback"].insert_one(data)

        return jsonify(success=True)


@app.route("/predict", methods=["GET", "POST"])
def predict():

    # Initialize the dictionary for the response.
    data = {"success": False}

    if request.method == "POST":
        # Grab and process the incoming json.
        start = time.time()
        incoming = request.get_json()
        url = incoming["url"]

        if url == '':
            return jsonify({'message': 'Maybe your input not correct'})

        data["predictions"] = []
        if (isinstance(url, str)):
            extracted_domain = tldextract.extract(url)
            domain = extracted_domain.domain+'.'+extracted_domain.suffix
            if whitelist.find_one({'url': domain}) is not None:
                return jsonify({"predictions": [{'result': 'This website may be safe', 'phishingPercentage': 0, 'url': url}]})
            if blackList.find_one({'url': domain}) is not None:
                return jsonify({"predictions": [{'result': 'This website may be phishing', 'phishingPercentage': 100, 'url': url}]})
            isAccessible, url, page = is_URL_accessible(url)
            if not isAccessible:
                return jsonify({'message': 'Sorry, we can not analyze this URL for now'})
            # cursor = dataset.find_one({'url': url})
            # if cursor is not None:
            #     features = []
            #     predi=0
            #     try:
            #         for i in range(len(mappingCriteria)):
            #             features.append(cursor[mappingCriteria[i]])
            #     except:
            #         pass
            #     try:
            #         predi = float(cursor["score"]) * 100
            #     except:
            #         predi = float(
            #             model.predict_proba([features])[0][1]) * 100
            #     result = ""
            #     try:
            #         if (cursor["status"] == "phishing"):
            #             result = "This website may be phishing"
            #         else:
            #             result = "This website may be safe"
            #     except:
            #         if (predi > 0.4):
            #             result = "This website may be phishing"
            #         else:
            #             result = "This website may be safe"
            #     extDetail = {}
            #     for i in range(len(features)):
            #         extDetail[mappingCriteria[i]] = features[i]
            #     r = {"result": result, "phishingPercentage": prediction,
            #          "url": url, "detail": extDetail}
            #     data["predictions"].append(r)
            #     data["success"] = True
            #     return jsonify(data)
            extractLink = url_extractor(url, page)
            if (extractLink == []):
                return jsonify({'message': 'Sorry, we can not analyze this URL for now'})
            prediction = model.predict_proba([extractLink])[0][1]
            end = time.time() - start

            if prediction > 0.4:
                result = "This website may be phishing"
            else:
                result = "This website may be safe"
            predictionPer = float(prediction) * 100
            extDetail = {}
            for i in range(len(extractLink)):
                extDetail[mappingCriteria[i]] = extractLink[i]

            r = {"result": result, "phishingPercentage": predictionPer,
                 "url": url, "detail": extDetail}
            data["predictions"].append(r)

            # Show that the request was a success.
            data["success"] = True
            data["time_elapsed"] = end

            # insertData = {}
            # insertData["url"] = url
            # insertData["score"] = prediction
            # for i in range(len(extractLink)):
            #     insertData[mappingCriteria[i]] = extractLink[i]
            # dataset.insert_one(insertData)

        else:
            if (isinstance(url, list)):
                listURLExtracted = []
                prediction = []
                pages = []
                for urlItem in url.copy():
                    isAccessible, newURL, page = is_URL_accessible(urlItem)
                    url[url.index(urlItem)] = newURL
                    pages.append(page)
                    if not isAccessible:
                        data['predictions'].append(
                            {'message': 'Sorry, we can not analyze this URL for now', 'url': newURL})
                        url.remove(newURL)
                        pages.remove(page)
                        continue
                    extracted_domain = tldextract.extract(newURL)
                    domain = extracted_domain.domain+'.'+extracted_domain.suffix
                    if whitelist.find_one({"url": domain}) is not None:
                        data['predictions'].append(
                            {'result': 'This website may be safe', 'phishingPercentage': 0, 'url': newURL})
                        url.remove(newURL)
                        pages.remove(page)
                        continue
                    if blackList.find_one({"url": domain}) is not None:
                        data['predictions'].append(
                            {'result': 'This website may be phishing', 'phishingPercentage': 100, 'url': newURL})
                        url.remove(newURL)
                        pages.remove(page)
                        continue
                    # cursor = dataset.find_one({'url': newURL})
                    # if cursor is not None:
                    #     features = []
                    #     predi=0
                    #     try:
                    #         for i in range(len(mappingCriteria)):
                    #             features.append(cursor[mappingCriteria[i]])
                    #     except:
                    #         pass
                    #     try:
                    #         prediPer = float(cursor["score"]) * 100
                    #     except:
                    #         predi = model.predict_proba([features])[0][1]
                    #         prediPer = float(predi) * 100
                    #     result = ""
                    #     try:
                    #         if (cursor["status"] == "phishing"):
                    #             result = "This website may be phishing"
                    #         else:
                    #             result = "This website may be safe"
                    #     except:
                    #         if (predi > 0.4):
                    #             result = "This website may be phishing"
                    #         else:
                    #             result = "This website may be safe"
                    #     extDetail = {}
                    #     for i in range(len(features)):
                    #         extDetail[mappingCriteria[i]] = features[i]
                    #     r = {"result": result, "phishingPercentage": prediPer,
                    #          "url": url, "detail": extDetail}
                    #     data["predictions"].append(r)
                    #     url.remove(newURL)
                    #     pages.remove(page)
                    #     continue
                if not url == []:
                    def extractURL(i):
                        return url_extractor(url[i], pages[i])

                    def predictProbabilities(feat):
                        return model.predict_proba([feat])
                    indexList = [i for i in range(len(url))]
                    with ThreadPoolExecutor(max_workers=18) as executor:
                        for result in executor.map(extractURL, indexList):
                            listURLExtracted.append(result)
                    with ThreadPoolExecutor(max_workers=18) as executor:
                        for result in executor.map(predictProbabilities, listURLExtracted):
                            prediction.append(result)
                    for i, pred in enumerate(prediction):
                        if pred[0][1] > 0.4:
                            result = "This website may be phishing"
                        else:
                            result = "This website may be safe"
                        prediPer = float(pred[0][1]) * 100
                        extDetail = {}
                        for j in range(len(listURLExtracted[i])):
                            extDetail[mappingCriteria[j]
                                      ] = listURLExtracted[i][j]

                        r = {"result": result, "phishingPercentage": prediPer,
                             "url": url[i], "detail": extDetail}
                        data["predictions"].append(r)
                        # insertData = {}
                        # insertData["url"] = url[i]
                        # insertData["score"] = pred[0][1]
                        # for z in range(len(listURLExtracted[i])):
                        #     insertData[mappingCriteria[i]
                        #                ] = listURLExtracted[i][z]
                        # dataset.insert_one(insertData)
                    end = time.time() - start
                    data["success"] = True
                    data["time_elapsed"] = end
        return jsonify(data)
    else:
        return jsonify({'message': 'Send me something'})


@app.route("/detail", methods=["GET", "POST"])
def detail():
    data = {"success": False}
    if request.method == "POST":
        start = time.time()
        incoming = request.get_json()
        url = incoming["url"]

        if url == '':
            return jsonify({'message': 'Maybe your input not correct'})

        if (isinstance(url, str)):
            isAccessible, newURL, page = is_URL_accessible(url)
            if not isAccessible:
                return jsonify({'message': 'Sorry, we can not analyze this URL for now'})
            extResult = url_extractor(newURL, page)
            end = time.time() - start

            # map extdetail with criteria to return as object
            extDetail = {}
            for i in range(len(extResult)):
                extDetail[mappingCriteria[i]] = extResult[i]
            data['detail'] = extDetail
            data["success"] = True
            data["time_elapsed"] = end
        return jsonify(data)
    else:
        return jsonify({'message': 'Send me something'})


# Start the server.
if __name__ == "__main__":
    print("Starting the server and loading the model...")
    app.run(host='0.0.0.0', port=45000, debug=True)
