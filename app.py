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
client = MongoClient("mongodb://localhost:27017")
db = client["phishing"]
blackList = db["blacklist"]
whitelist = db["whiteList"]

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


# @app.route('/survey', methods=["GET", "POST"])
# def survey():

#     features = {
#         'Chứa địa chỉ IP trong URL': 'Các trang web lừa đảo thường không đăng ký tên miền thay vào đó là sử dụng nguyên IP vì vậy hãy cẩn thận',
#         'Chứa ký tự @ trong URL': 'Dấu @ có tác dụng bỏ quả tất cả ký tự xuất hiện trước nó (VD: http://totally-legit-site.com@192.168.50.20/account sẽ đưa nạn nhân đến trang 192.168.50.20/account là trang web lửa đảo',
#         'Địa chỉ trang web chứa nhiều path': 'Tìm kiếm điểm chung của trang web lừa đảo giựa vào số đường dẫn có trong url',
#         'Có ký tự // trong tên miền': 'Ký tự // nằm trong đường dẫn nhằm chuyển hướng người dùng đến trang web lừa đảo',
#         'HTTPS hoặc HTTP trong tên miền': 'sử dụng https trong domain khiến người dùng nhìn nhầm và chủ quan (VD: http:https://vietcombank.com.vn)',
#         'Sử dụng địa chỉ rút gọn': 'Sử dụng địa chỉ rút gọn như bit.ly để giấu đi địa chỉ thật sự của trang web lừa đảo',
#         'Có chứa ký tự - trong domain': 'sử dụng ký tự - trong tên miền khiến tên trang web nhìn "có vẻ" không lừa đảo',
#         'Kiểm tra xem DNS có nhận được website không': 'Kiểm tra xem DNS có trỏ đến được trang web không, nếu không thì trang web đó được đăng ký với dịch vụ không rõ ràng',
#         'Tuổi thọ của tên miền có dưới 6 tháng': 'Nhưng trang web lừa đảo thường bị báo cáo liên tục đẫn đến việc gỡ xuống và nhưng tên lừa đảo thường không hay bỏ chi phí duy trì server nên tuổi thọ thường rất ngắn',
#         'Tên miền đã hết hạn': 'Tên miền đã hết hạn đăng ký',
#         'Website có sử dụng Iframe': 'Sử dụng Iframe chạy chầm trong các trang web để ăn cắp thông tin cá nhân',
#         'Website có sử dụng Mouse_Over': 'Sử dụng hàm mouse_over trong javscript để khi người dùng đung đưa con chuột qua 1 cái link bất kỳ trang web lừa đảo sẽ tự động bật lên',
#         'Website tắt chức năng Right_Click': 'Trang web vô hiệu hóa chuột phải vì lo sợ ta sẽ nhìn thấy những đoạn mã độc trong trang web',
#         'Sô lần bị forward có quá 2 lần khi vào trang web': 'Khi vào 1 trang web số lần ta bị tự động forward quá nhiều nhằm qua mặt các công cụ quét',
#         'Địa chỉ Website có chứa punny code': 'Sử dụng punnycode để đánh lừa url (VD: dı sẽ nhìn khá giống với di nhưng punnycode của adıdas.de là trang web lừa đảo với đủ ký tự là http://xn--addas-o4a.de/ nhưng trình duyệt sẽ encode và hiển thị giống như là adidas.de'
#     }
#     sublist = [list(features.keys())[n:n+3]
#                for n in range(0, len(list(features.keys())), 3)]
#     if request.method == "POST" and request.form['url'] != None:
#         url = request.form['url']

#         if url == '':
#             return jsonify({'notvalid': 'Maybe your input not correct'})

#         if (isinstance(url, str)):
#             url_prepped = preprocess_url(url, tokenizer)
#             prediction = model.predict(url_prepped)

#             if prediction > 0.5:
#                 return jsonify({'notsafe': 'Website Phishing ', 'score': str(prediction[0][0])})
#             else:
#                 return jsonify({'safe': 'Website Legitimate', 'score': str(prediction[0][0])})

#         # return render_template('index.html',data=sublist,features=features)

#     return render_template('index.html', data=sublist, features=features)


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
            if not is_URL_accessible(url):
                return jsonify({'message': 'Sorry, we can not analyze this URL for now'})
            extractLink = url_extractor(url)
            if (extractLink == []):
                return jsonify({'message': 'Sorry, we can not analyze this URL for now'})
            prediction = model.predict_proba([extractLink])[0][1]
            end = time.time() - start

            if prediction > 0.4:
                result = "This website may be phishing"
            else:
                result = "This website may be safe"
            prediction = float(prediction)
            prediction = prediction * 100
            extDetail = {}
            for i in range(len(extractLink)):
                extDetail[mappingCriteria[i]] = extractLink[i]

            r = {"result": result, "phishingPercentage": prediction,
                 "url": url, "detail": extDetail}
            data["predictions"].append(r)

            # Show that the request was a success.
            data["success"] = True
            data["time_elapsed"] = end

        else:
            # Check for base URL. Accuracy is not as great.
            def extractURL(url):
                if not is_URL_accessible(url):
                    return []
                return url_extractor(url)

            def predictURL(feat):
                rel = []
                if feat == []:
                    return rel
                try:
                    rel = model.predict_proba([feat])
                except:
                    rel = []
                return rel
            if (isinstance(url, list)):
                listURLExtracted = []
                prediction = []
                with ThreadPoolExecutor(max_workers=16) as executor:
                    for result in executor.map(extractURL, url):
                        listURLExtracted.append(result)
                with ThreadPoolExecutor(max_workers=16) as executor:
                    for result in executor.map(predictURL, listURLExtracted):
                        prediction.append(result)
                for i, pred in enumerate(prediction):
                    if pred == []:
                        data["predictions"].append(
                            {"message": "Sorry, we can not analyze this URL for now", "url": url[i]})
                        continue
                    if pred[0][1] > 0.4:
                        result = "This website may be phishing"
                    else:
                        result = "This website may be safe"
                    pred = float(pred[0][1])
                    pred = pred * 100
                    extDetail = {}
                    for j in range(len(listURLExtracted[i])):
                        extDetail[mappingCriteria[j]] = listURLExtracted[i][j]
                    r = {"result": result, "phishingPercentage": pred,
                         "url": url[i], "detail": extDetail}
                    data["predictions"].append(r)
                end = time.time() - start
                # Show that the request was a success.
                data["success"] = True
                data["time_elapsed"] = end

        # Return the data as a JSON response.
        return jsonify(data)
    else:
        return jsonify({'message': 'Send me something'})


# @app.route("/detail", methods=["GET", "POST"])
# def detail():
#     data = {"success": False}
#     if request.method == "POST":
#         start = time.time()
#         incoming = request.get_json()
#         url = incoming["url"]

#         if url == '':
#             return jsonify({'message': 'Maybe your input not correct'})

#         ext = Extractor()
#         if (isinstance(url, str)):
#             extResult = ext(url)
#             end = time.time() - start

#             # map extdetail with criteria to return as object
#             extDetail = {}
#             for i in range(len(extResult)):
#                 extDetail[mappingCriteria[i]] = extResult[i]
#             data['detail'] = extDetail
#             data["success"] = True
#             data["time_elapsed"] = end
#         return jsonify(data)
#     else:
#         return jsonify({'message': 'Send me something'})


# Start the server.
if __name__ == "__main__":
    print("Starting the server and loading the model...")
    app.run(host='0.0.0.0', port=45000, debug=True)
