from flask import Flask, render_template, jsonify, request, session, redirect, url_for

app = Flask(__name__)
import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient

# client = MongoClient('mongodb://test:test@localhost', 27017)
client = MongoClient('localhost', 27017)
db = client.Shoe

# JWT 토큰을 만들 때 필요한 비밀문자열입니다. 아무거나 입력해도 괜찮습니다.
# 이 문자열은 서버만 알고있기 때문에, 내 서버에서만 토큰을 인코딩(=만들기)/디코딩(=풀기) 할 수 있습니다.
SECRET_KEY = 'SPARTA'

# JWT 패키지를 사용합니다. (설치해야할 패키지 이름: PyJWT)
import jwt

# 토큰에 만료시간을 줘야하기 때문에, datetime 모듈도 사용합니다.
import datetime

# 회원가입 시엔, 비밀번호를 암호화하여 DB에 저장해두는 게 좋습니다.
# 그렇지 않으면, 개발자(=나)가 회원들의 비밀번호를 볼 수 있으니까요.^^;
import hashlib


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
        return redirect(url_for("login", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        return redirect(url_for("login"))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/mypage')
def mypage():
    token_receive = request.cookies.get('mytoken')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.user.find_one({"id": payload['id']})
        return render_template('mypage.html', nickname=user_info["nick"])
    except jwt.ExpiredSignatureError:
        return redirect(url_for("login", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        return redirect(url_for("login"))

#################################
##  로그인을 위한 API            ##
#################################

# [회원가입 API]
# id, pw, nickname을 받아서, mongoDB에 저장합니다.
# 저장하기 전에, pw를 sha256 방법(=단방향 암호화. 풀어볼 수 없음)으로 암호화해서 저장합니다.
@app.route('/api/register', methods=['POST'])
def api_register():
    id_receive = request.form['id_give']
    pw_receive = request.form['pw_give']
    nickname_receive = request.form['nickname_give']

    db_name = db.user.find_one({'id': id_receive})
    db_nick = db.user.find_one({'nick': nickname_receive})
    if (id_receive == "" or pw_receive == "" or nickname_receive == ""):
        return jsonify({'result': "fail", 'msg': '빈 항목이 있습니다.'})
    elif(id_receive == db_name):
        return jsonify({'result': 'fail', 'msg': "이미 사용중인 아이디입니다."})
    elif(nickname_receive == db_nick):
        return jsonify({'result': 'fail', 'msg': '이미 사용중인 닉네임입니다.'})
    pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest()

    db.user.insert_one({'id': id_receive, 'pw': pw_hash, 'nick': nickname_receive})

    return jsonify({'result': 'success'})


# [로그인 API]
# id, pw를 받아서 맞춰보고, 토큰을 만들어 발급합니다.
@app.route('/api/login', methods=['POST'])
def api_login():
    id_receive = request.form['id_give']
    pw_receive = request.form['pw_give']

    if (id_receive == "" or pw_receive == ""):
        return jsonify({'result': 'fail', 'msg': "입력할 수 없는 아이디/비밀번호입니다."})
    # 회원가입 때와 같은 방법으로 pw를 암호화합니다.
    pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest()

    # id, 암호화된 pw을 가지고 해당 유저를 찾습니다.
    result = db.user.find_one({'id': id_receive, 'pw': pw_hash})

    # 찾으면 JWT 토큰을 만들어 발급합니다.
    if result is not None:
        # JWT 토큰에는, payload와 시크릿키가 필요합니다.
        # 시크릿키가 있어야 토큰을 디코딩(=풀기) 해서 payload 값을 볼 수 있습니다.
        # 아래에선 id와 exp를 담았습니다. 즉, JWT 토큰을 풀면 유저ID 값을 알 수 있습니다.
        # exp에는 만료시간을 넣어줍니다. 만료시간이 지나면, 시크릿키로 토큰을 풀 때 만료되었다고 에러가 납니다.
        payload = {
            'id': id_receive,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=60 * 60)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256').decode('utf-8')

        # token을 줍니다.
        return jsonify({'result': 'success', 'token': token})
    # 찾지 못하면
    else:
        return jsonify({'result': 'fail', 'msg': '아이디/비밀번호가 일치하지 않습니다.'})


# [유저 정보 확인 API]
# 로그인된 유저만 call 할 수 있는 API입니다.
# 유효한 토큰을 줘야 올바른 결과를 얻어갈 수 있습니다.
# (그렇지 않으면 남의 장바구니라든가, 정보를 누구나 볼 수 있겠죠?)
@app.route('/api/nick', methods=['GET'])
def api_valid():
    token_receive = request.cookies.get('mytoken')

    # try / catch 문?
    # try 아래를 실행했다가, 에러가 있으면 except 구분으로 가란 얘기입니다.

    try:
        # token을 시크릿키로 디코딩합니다.
        # 보실 수 있도록 payload를 print 해두었습니다. 우리가 로그인 시 넣은 그 payload와 같은 것이 나옵니다.
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        print(payload)

        # payload 안에 id가 들어있습니다. 이 id로 유저정보를 찾습니다.
        # 여기에선 그 예로 닉네임을 보내주겠습니다.
        userinfo = db.user.find_one({'id': payload['id']}, {'_id': 0})
        return jsonify({'result': 'success', 'nickname': userinfo['nick']})
    except jwt.ExpiredSignatureError:
        # 위를 실행했는데 만료시간이 지났으면 에러가 납니다.
        return jsonify({'result': 'fail', 'msg': '로그인 시간이 만료되었습니다.'})
    except jwt.exceptions.DecodeError:
        return jsonify({'result': 'fail', 'msg': '로그인 정보가 존재하지 않습니다.'})

# 메인페이지(DB)
def shoes_data():
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

def notices_data():
    db.notices.remove({})
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36'}
    data = requests.get('https://www.shoeprize.com/shoeprize/?p=0', headers=headers)
    soup = BeautifulSoup(data.text, 'html.parser')
    notices = soup.select('body > div.container > div.content > ul > li')
    for notice in notices:
        image = notice.select_one('a > div.img_area > img')['data-src']
        title = notice.select_one('a > div.info_area > div.post_title').text
        content = notice.select_one('a > div.info_area > div.post_content').text
        info = notice.select_one('a > div.info_area > div.detail_info').text
        link = notice.select_one('a')['href']
        doc = {
            'image': image,
            'title': title,
            'content': content,
            'info': info,
            'link': link,
        }
        db.notices.insert_one(doc)
###################################
##  index.html 연결 API을 주는 부분  ##

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

@app.route('/api/list/event', methods=['GET'])
def show_notices():
    notices_data()
    lists_3 = list(db.notices.find({}, {'_id': False}))
    return jsonify({'result': 'success', 'all_lists3': lists_3})

# 마이페이지 스크랩
@app.route('/api/list/mine', methods=['POST'])
def show_myshoes():
    image_receive = request.form['image_give']
    shop_receive = request.form['shop_give']
    shoe_receive = request.form['shoe_give']
    country_receive = request.form['country_give']
    link_receive = request.form['link_give']
    db.myshoes.insert_one({'image': image_receive,
                           'shop': shop_receive,
                           'shoe': shoe_receive,
                           'country': country_receive,
                           'link': link_receive})
    return jsonify({'result': 'success'})

@app.route('/api/list/oldmine', methods=['POST'])
def show_oldmyshoes():
    image_receive = request.form['image_give']
    shop_receive = request.form['shop_give']
    shoe_receive = request.form['shoe_give']
    country_receive = request.form['country_give']
    link_receive = request.form['link_give']
    db.oldmyshoes.insert_one({'image': image_receive,
                              'shop': shop_receive,
                              'shoe': shoe_receive,
                              'country': country_receive,
                              'link': link_receive})
    return jsonify({'result': 'success'})

@app.route('/api/list/myevent')
def show_mynotices():
    image_receive = request.form['image_give']
    title_receive = request.form['title_give']
    content_receive = request.form['content_give']
    info_receive = request.form['info_give']
    link_receive = request.form['link_give']
    db.mynotices.insert_one({'image': image_receive,
                              'title': title_receive,
                              'content': content_receive,
                              'info': info_receive,
                              'link': link_receive})
    return jsonify({'result': 'success'})
# mypage.html 연결 API
@app.route('/api/mypage/mynew', methods=['GET'])
def show_scrapmyshoes():
    scrap_list = list(db.myshoes.find({}, {'_id': False}))
    return jsonify({'result': 'success', 'all_list3': scrap_list})

@app.route('/api/mypage/myold', methods=['GET'])
def show_scrapmyoldshoes():
    scrap_list = list(db.oldmyshoes.find({}, {'_id': False}))
    return jsonify({'result': 'success', 'all_list3': scrap_list})

# mypage.html 스크랩 삭제 API
@app.route('/api/mypage/noshoes', methods=['POST'])
def delete_myshoes():
    shop_receive = request.form['shop_give']
    shoe_receive = request.form['shoe_give']
    country_receive = request.form['country_give']

    db.myshoes.remove({'shop': shop_receive,
                       'shoe': shoe_receive,
                       'country': country_receive})
    return jsonify({'result': 'success'})

@app.route('/api/mypage/nooldshoes', methods=['POST'])
def delete_myoldshoes():
    shop_receive = request.form['shop_give']
    shoe_receive = request.form['shoe_give']
    country_receive = request.form['country_give']

    db.oldmyshoes.remove({'shop': shop_receive,
                          'shoe': shoe_receive,
                          'country': country_receive})
    return jsonify({'result': 'success'})

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)