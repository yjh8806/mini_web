from flask import Flask, render_template, jsonify, request, session, redirect, url_for
import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient

# to encrypt PW
import jwt
# 토큰에 만료시간을 줘야하기 때문에, datetime 모듈도 사용
import datetime
# 회원가입 시엔, 비밀번호를 암호화하여 DB에 저장
# 그렇지 않으면, 개발자(=나)가 회원들의 비밀번호를 볼 수 있음
import hashlib
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
# 순서 섞기
import random

# JWT 토큰을 만들 때 필요한 비밀문자열. 아무거나 입력O
# 이 문자열은 서버만 알고있기 때문에, 내 서버에서만 토큰을 인코딩(=만들기)/디코딩(=풀기) 가능
SECRET_KEY = 'SPARTA'

app = Flask(__name__)

client = MongoClient('localhost', 27017)
db = client.Shoe

def shoes_data():
    # db.shoes.drop()
    db.shoes.remove({})
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36'}
    data = requests.get('https://www.shoeprize.com/today/', headers=headers)
    soup = BeautifulSoup(data.text, 'html.parser')

    trs = soup.select('body > div.container > div.content > div.product_list_area.current_list > ul > li')
    for tr in trs:
        image = tr.select_one('div.img_area > a > img')['data-src']
        shop = tr.select_one('div.info_area > div.text_area > div.brand > a').text
        shoe = tr.select_one('div.info_area > div.text_area > div.name').text
        country = tr.select_one('div.info_area > div.text_area > div.delivery').text
        link = tr.select_one('div.img_area > a')['href']
        doc = {
            'image': image,
            'shop': shop,
            'shoe': shoe,
            'country': country,
            'link': link,
        }
        db.shoes.insert_one(doc)

def oldShoes_data():
    db.old_shoes.remove({})
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36'}
    data = requests.get('https://www.shoeprize.com/today/', headers=headers)
    soup = BeautifulSoup(data.text, 'html.parser')
    old_shoes = soup.select('body > div.container > div.content > div:nth-child(5) > ul > li')
    for old_shoe in old_shoes:
        image = old_shoe.select_one('div.img_area > a > img')['data-src']
        shop = old_shoe.select_one('div.info_area > div.text_area > div.brand > a').text
        shoe = old_shoe.select_one('div.name').text
        country = old_shoe.select_one('div.delivery').text
        link = old_shoe.select_one('div.img_area > a')['href']

        doc = {
            'image': image,
            'shop': shop,
            'shoe': shoe,
            'country': country,
            'link': link,
        }
        db.old_shoes.insert_one(doc)
#################################
##  HTML을 주는 부분             ##
#################################
@app.route('/')
def home():
    token_receive = request.cookies.get('mytoken')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.user.find_one({"id": payload['id']})
        return render_template('index.html', nickname=user_info["nick"])
    except jwt.ExpiredSignatureError:
        return redirect(url_for("login", msg="time has been expired"))
    except jwt.exceptions.DecodeError:
        return redirect(url_for("login", msg="Login Failed"))

@app.route('/login')
def login():
    msg = request.args.get("msg")
    return render_template('login.html', msg=msg)

@app.route('/sign_in', methods=['POST'])
def sign_in():
    # 로그인
    username_receive = request.form['username_give']
    password_receive = request.form['password_give']
    pw_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
    result = db.users.find_one({'username': username_receive, 'password': pw_hash})
    if result is not None:
        payload = {
         'id': username_receive,
         'exp': datetime.utcnow() + timedelta(seconds=60 * 60)  # login 1hr
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256').decode('utf-8')
        return jsonify({'result': 'success', 'token': token})
    # 찾지 못하면
    else:
        return jsonify({'result': 'fail', 'msg': 'ID or password does not match.'})

@app.route('/sign_up/save', methods=['POST'])
def sign_up():
    username_receive = request.form['username_give']
    password_receive = request.form['password_give']
    password_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
    doc = {
        "username": username_receive,
        "password": password_hash,
        "profile_name": username_receive,
    }
    db.users.insert_one(doc)
    return jsonify({'result': 'success'})

@app.route('/sign_up/check_dup', methods=['POST'])
def check_dup():
    username_receive = request.form['username_give']
    exists = bool(db.users.find_one({"username": username_receive}))
    # print(value_receive, type_receive, exists)
    return jsonify({'result': 'success', 'exists': exists})

@app.route('/api/mypage', methods=['GET'])
def tomypage():
    msg = request.args.get("msg")
    return render_template('mypage.html', msg=msg)
# 메인 페이지
@app.route('/api/list/new', methods=['GET'])
def show_shoes():
    shoes_data()
    lists = list(db.shoes.find({}, {'_id': False}))
    return jsonify({'result': 'success', 'all_lists': lists})

@app.route('/api/list/ended', methods=['GET'])
def show_oldShoes():
    oldShoes_data()
    lists_2 = list(db.old_shoes.find({}, {'_id': False}))
    return jsonify({'result': 'success', 'all_lists2': lists_2})

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)