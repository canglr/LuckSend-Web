import base64
import urllib
import uuid
from random import randint
from urllib.parse import urlparse

from bson import SON
from dateutil.relativedelta import relativedelta
import shortuuid as shortuuid
from cryptography.fernet import Fernet
from flask import Flask, redirect, request, url_for, session, json, jsonify, send_file
from flask_babel import Babel, gettext
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask import render_template
from requests import HTTPError
from requests_oauthlib import OAuth2Session
from datetime import datetime, timedelta
from sqlalchemy import func
import ssl
from pymongo import MongoClient
from sqlalchemy import desc
from bs4 import BeautifulSoup

app = Flask(__name__)
POSTGRES = {
    'user': 'lucksend',
    'pw': 'XD9pLYDxaqZHlJaBVSum6uWIyC4Q1Dob',
    'db': 'Raffles',
    'host': '127.0.0.1',
    'port': '5432',
}
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:\
%(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "6aW9HNLt7IncD6PDwo4Q9C0eUBKnXO1W"
app.config['AES_KEY'] = "qlEVOu1ZSu3-KDMh1qVMtjIT8UepTyZFXvVRrJZ_AV0="
app.config.from_pyfile('settings.cfg')
babel = Babel(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "6aW9HNLt7IncD6PDwo4Q9C0eUBKnXO1W"


client = MongoClient('mongodb+srv://lucksend:sXu2x4z6@lucksend-echos.mongodb.net/admin?retryWrites=true&w=majority')
mongodb = client['lucksend']
InstagramProfile = mongodb['InstagramProfile']
UserKeytoId = mongodb['UserKeytoId']
SocialMedia = mongodb['SocialMedia']
Search = mongodb['Search']


class Auth:
    CLIENT_ID = ('8dmftdap4pu55gmpn21aeilk4t2o7eau'
                 '.apps.googleusercontent.com')
    CLIENT_SECRET = '51VX-mKxb'
    REDIRECT_URI = 'https://lucksend.com/gCallback'
    AUTH_URI = 'https://accounts.google.com/o/oauth2/auth'
    TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'
    USER_INFO = 'https://www.googleapis.com/userinfo/v2/me'
    SCOPE = ['profile', 'email', 'openid']


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mail_adress = db.Column(db.String, nullable=False)
    name = db.Column(db.String, nullable=False)
    profile_picture = db.Column(db.String, nullable=False)
    local = db.Column(db.String, nullable=False)
    provider_name = db.Column(db.String, nullable=False)
    provider_id = db.Column(db.String, nullable=False)
    id_share = db.Column(db.String, nullable=False, unique=True)
    is_active = db.Column(db.Boolean, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    last_update = db.Column(db.DateTime, nullable=False)
    raffleslerf = db.relationship('Raffles', backref='users', lazy=True)
    feedbacksf = db.relationship('Feedbacks', backref='users', lazy=True)
    participantsf = db.relationship('Participants', backref='users', lazy=True)
    keysf = db.relationship('Keys', backref='users', lazy=True)
    luckysf = db.relationship('Luckys', backref='users', lazy=True)
    qrcodesf = db.relationship('Qrcode', backref='users', lazy=True)
    socialstatisticssf = db.relationship('Socialstatistics', backref='users', lazy=True)
    socialsavedf = db.relationship('Socialsaved', backref='users', lazy=True)
    socialreportssf = db.relationship('Socialreports', backref='users', lazy=True)

    def get_id(self):
        return self.id

    def is_authenticated(self):
        return True

    def is_activex(self):  # line 37
        return self.is_active

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    # Required for administrative interface
    def __unicode__(self):
        return self.username


class Raffles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_share = db.Column(db.String, nullable=False,unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),nullable=False)
    title = db.Column(db.String, nullable=False)
    contact_information = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.Boolean, nullable=False)
    processing = db.Column(db.Boolean, nullable=False)
    completed = db.Column(db.Boolean, nullable=False)
    delete = db.Column(db.Boolean, nullable=False)
    disable = db.Column(db.Boolean, nullable=False)
    winners = db.Column(db.Integer, nullable=False)
    reserves = db.Column(db.Integer, nullable=False)
    raffle_date = db.Column(db.DateTime, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    last_update = db.Column(db.DateTime, nullable=False)
    luckysf = db.relationship('Luckys', backref='raffles', lazy=True)
    tagstargetf = db.relationship('Tagtargets', backref='raffles', lazy=True)
    countrytargetf = db.relationship('Countrytargets', backref='raffles', lazy=True)


class Feedbacks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),nullable=False)
    description = db.Column(db.String, nullable=False)
    read = db.Column(db.Boolean, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    last_update = db.Column(db.DateTime, nullable=False)


class Participants(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),nullable=False)
    raffle_id = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)


class Keys(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),nullable=False)
    key = db.Column(db.String, nullable=False)
    device_key = db.Column(db.String, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)
    device_information_id = db.Column(db.Integer, db.ForeignKey('deviceinformation.id'),nullable=False)


class Luckys(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),nullable=False)
    raffles_id = db.Column(db.Integer, db.ForeignKey('raffles.id'),nullable=False)
    secret_key = db.Column(db.String, nullable=False, unique=True)
    status = db.Column(db.Boolean, nullable=False)
    check_key = db.Column(db.Boolean, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)


class Deviceinformation(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    brand = db.Column(db.String,nullable=False)
    model = db.Column(db.String,nullable=False)
    release = db.Column(db.String,nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    keysf = db.relationship('Keys', backref='deviceinformation', lazy=True)


class Tags(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    tag_name = db.Column(db.String,nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    tagsf = db.relationship('Tagtargets', backref='tags', lazy=True)


class Tagtargets(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    tag_id = db.Column(db.Integer, db.ForeignKey('tags.id'),nullable=False)
    raffle_id = db.Column(db.Integer, db.ForeignKey('raffles.id'),nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)


class Countries(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    country_code = db.Column(db.String, nullable=False)
    Countriesf = db.relationship('Countrytargets', backref='countries', lazy=True)


class Countrytargets(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    country_id = db.Column(db.Integer, db.ForeignKey('countries.id'), nullable=False)
    raffle_id = db.Column(db.Integer, db.ForeignKey('raffles.id'), nullable=False)


class Countrymultilang(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    multi_code = db.Column(db.String, nullable=True)
    country_code = db.Column(db.String, nullable=False)
    country_name = db.Column(db.String, nullable=False)


class Versions(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    versions_name = db.Column(db.String,nullable=False)
    versions_description = db.Column(db.String,nullable=True)
    versions_code = db.Column(db.String,nullable=False)
    versions_secret_key = db.Column(db.String,nullable=False)
    contact_secret_key = db.Column(db.String,nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)


class Logs(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address = db.Column(db.String, nullable=False)
    action = db.Column(db.String,nullable=False)
    data = db.Column(db.JSON,nullable=True)
    creation_date = db.Column(db.DateTime, nullable=False)


class Qrcode(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    key = db.Column(db.String,nullable=False)
    status = db.Column(db.Boolean,nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)


class Socialmedia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_share = db.Column(db.String, nullable=False, unique=True)
    author_name = db.Column(db.String, nullable=False)
    media_id = db.Column(db.String, nullable=False)
    media_description = db.Column(db.String, nullable=False)
    media_image = db.Column(db.String, nullable=False)
    media_url = db.Column(db.String, nullable=False)
    provider_name = db.Column(db.String,nullable=False)
    delete = db.Column(db.Boolean, nullable=False)
    disable = db.Column(db.Boolean, nullable=False)
    verification = db.Column(db.Boolean, nullable=False)
    sponsor = db.Column(db.Boolean,nullable=False)
    type = db.Column(db.Boolean, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    last_update = db.Column(db.DateTime, nullable=False)
    socialtagtargetsf = db.relationship('Socialtagtargets', backref='socialmedia', lazy=True)
    socialsavedf = db.relationship('Socialsaved', backref='socialmedia', lazy=True)
    socialstatisticsf = db.relationship('Socialstatistics', backref='socialmedia', lazy=True)
    socialcountrytargetsf = db.relationship('Socialcountrytargets', backref='socialmedia', lazy=True)
    socialreportsf = db.relationship('Socialreports', backref='socialmedia', lazy=True)


class Socialtagtargets(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    tag_id = db.Column(db.Integer, db.ForeignKey('tags.id'), nullable=False)
    social_id = db.Column(db.Integer, db.ForeignKey('socialmedia.id'), nullable=False)


class Socialcountrytargets(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    country_id = db.Column(db.Integer, db.ForeignKey('countries.id'), nullable=False)
    social_id = db.Column(db.Integer, db.ForeignKey('socialmedia.id'), nullable=False)


class Socialstatistics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    social_id = db.Column(db.Integer, db.ForeignKey('socialmedia.id'), nullable=False)
    clicks = db.Column(db.Boolean, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)


class Socialsaved(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    social_id = db.Column(db.Integer, db.ForeignKey('socialmedia.id'), nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)


class Socialreports(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    social_id = db.Column(db.Integer, db.ForeignKey('socialmedia.id'), nullable=False)
    description = db.Column(db.String, nullable=False)
    read = db.Column(db.Boolean, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)


def get_google_auth(state=None, token=None):
    if token:
        return OAuth2Session(Auth.CLIENT_ID, token=token)
    if state:
        return OAuth2Session(
            Auth.CLIENT_ID,
            state=state,
            redirect_uri=Auth.REDIRECT_URI)
    oauth = OAuth2Session(
        Auth.CLIENT_ID,
        redirect_uri=Auth.REDIRECT_URI,scope=Auth.SCOPE)
    return oauth


def uuid_short():
    sec = randint(0, 2)
    if sec == 0:
        sonuc = shortuuid.ShortUUID().random(length=8)
    elif sec == 1:
        sonuc = shortuuid.ShortUUID().random(length=10)
    elif sec == 2:
        sonuc = shortuuid.ShortUUID().random(length=12)
    return sonuc


def aes_encode(text):
    """key = Fernet.generate_key()"""
    f = Fernet(bytes(app.config['AES_KEY'], 'utf-8'))
    encode_text = f.encrypt(bytes(text, 'utf-8'))
    return encode_text.decode("utf-8")


def aes_decode(text):
    f = Fernet(bytes(app.config['AES_KEY'], 'utf-8'))
    decode_text = f.decrypt(bytes(text, 'utf-8'))
    return decode_text.decode("utf-8")


def get_ip():
    ip = request.access_route[0]
    return ip


def session_id_create():
    if session.get('id', '') is '':
        session['id'] = uuid.uuid4()


def session_get_redirect():
    if session.get('redirect', '') is '':
        redirect_to = "/"
    else:
        redirect_to = session.get('redirect', '')
    session["redirect"] = ""
    return redirect_to


def get_browser_country():
    try:
        data = list(request.accept_languages[0][0])
        if len(data) == 5:
            result = data[3] + data[4]
            return result.lower()
        else:
            result = data[0] + data[1]
            return result.lower()
    except IndexError:
        return 'us'


@app.context_processor
def jinja_get_browser_country():
    try:
        data = list(request.accept_languages[0][0])
        if len(data) == 5:
            result = data[3] + data[4]
            return dict(get_browser_country=result.lower())
        else:
            result = data[0] + data[1]
            return dict(get_browser_country=result.lower())
    except IndexError:
        return 'us'


def get_browser_lang():
    try:
        data = list(request.accept_languages[0][0])
        result = data[0] + data[1]
        return result
    except IndexError:
        return 'en'


@babel.localeselector
def get_locale():
    # if a user is logged in, use the locale from the user settings
    supported_locale = ['tr', 'en']
    if current_user.is_authenticated:
        locale = current_user.local
        if locale is not None:
            if locale in supported_locale:
                return locale
            else:
                return 'en'
    else:
        try:
            locale = get_browser_lang()
            if locale is not None:
                if locale in supported_locale:
                    return locale
                else:
                    return 'en'
        except IndexError:
            return 'en'

    # otherwise try to guess the language from the user accept
    # header the browser transmits.  We support de/fr/en in this
    # example.  The best match wins.
    # return request.accept_languages.best_match(['tr', 'en'],'en')


def add_log(action,data):
    log = Logs()
    log.user_id = current_user.id
    log.ip_address = get_ip()
    log.action = action
    log.data = data
    log.creation_date = datetime.utcnow()
    db.session.add(log)
    db.session.commit()
    return True


def add_tags(tags,raffle_id):
    tagtarget_count = Tagtargets.query.filter_by(raffle_id=raffle_id).count()
    if tagtarget_count is not 0:
        db.session.query(Tagtargets).filter_by(raffle_id=raffle_id).delete()

    for tag in tags:
        tag_check = Tags.query.filter_by(tag_name=tag).first()
        if tag_check is not None:
            add_tagtarget = Tagtargets()
            add_tagtarget.tag_id = tag_check.id
            add_tagtarget.raffle_id = raffle_id
            add_tagtarget.creation_date = datetime.utcnow()
            db.session.add(add_tagtarget)
            db.session.commit()
        else:
            add_tag = Tags()
            add_tag.tag_name = tag
            add_tag.creation_date = datetime.utcnow()
            db.session.add(add_tag)
            db.session.commit()

            add_tagtarget = Tagtargets()
            add_tagtarget.tag_id = add_tag.id
            add_tagtarget.raffle_id = raffle_id
            add_tagtarget.creation_date = datetime.utcnow()
            db.session.add(add_tagtarget)
            db.session.commit()

    return None


def add_countries(countries,raffle_id):
    db.session.query(Countrytargets).filter_by(raffle_id=raffle_id).delete()
    if len(countries) is not 1:
        try:
            countries.remove("ALL")
            pass
        except ValueError:
            pass

    for country in countries:
        country_info = Countries.query.filter_by(country_code=country).first()
        add_country = Countrytargets()
        add_country.country_id = country_info.id
        add_country.raffle_id = raffle_id
        db.session.add(add_country)
        db.session.commit()
        print(country)
    return None


def raffle_check_country(raffle_id):
    country = current_user.local.upper()
    country_info_all = Countries.query.filter_by(country_code='ALL').first()
    if country_info_all is not None:
        country_check = Countrytargets.query.filter_by(raffle_id=raffle_id).filter_by(
            country_id=country_info_all.id).first()
        if country_check is not None:
            return True
        else:
            country_info = Countries.query.filter_by(country_code=country).first()
            if country_info is not None:
                country_check = Countrytargets.query.filter_by(raffle_id=raffle_id).filter_by(
                    country_id=country_info.id).first()
                if country_check is not None:
                    return True
                else:
                    return False
            else:
                return False
    else:
        return False


def cache_expiration(hours):
    date = datetime.utcnow() + relativedelta(hours=+hours)
    return date


def date_back_to(hours):
    date = datetime.utcnow() + relativedelta(hours=-hours)
    return date


def instagram_profile_image(user_name):
    try:
        image_check = InstagramProfile.find_one({"author_name": user_name})
        if image_check is not None:
            return image_check['author_image']
        else:
            with urllib.request.urlopen("https://www.instagram.com/" + user_name + "/") as url:
                data = url.read()
                html = BeautifulSoup(data, 'html.parser')
                image = html.find('meta', property="og:image")
                InstagramProfile.insert_one({"author_name": user_name, "author_image": image['content'],
                                             "cache_expiration": cache_expiration(12)})
        return image["content"]
    except:
        return '/static/themes/social/images/no-profile.png'


def socialmedia_statistics(user_id,social_id,clicks):
    statistics = Socialstatistics()
    statistics.user_id = user_id
    statistics.social_id = social_id
    statistics.clicks = clicks
    statistics.creation_date = datetime.utcnow()
    db.session.add(statistics)
    db.session.commit()
    return True


def add_social_tags(tags,social_id):
    tagtarget_count = Socialtagtargets.query.filter_by(social_id=social_id).count()
    if tagtarget_count is not 0:
        db.session.query(Socialtagtargets).filter_by(social_id=social_id).delete()

    for tag in tags:
        tag_check = Tags.query.filter_by(tag_name=tag.strip()).first()
        if tag_check is not None:
            add_tagtarget = Socialtagtargets()
            add_tagtarget.tag_id = tag_check.id
            add_tagtarget.social_id = social_id
            db.session.add(add_tagtarget)
            db.session.commit()
        else:
            add_tag = Tags()
            add_tag.tag_name = tag.strip()
            add_tag.creation_date = datetime.utcnow()
            db.session.add(add_tag)
            db.session.commit()

            add_tagtarget = Socialtagtargets()
            add_tagtarget.tag_id = add_tag.id
            add_tagtarget.social_id = social_id
            db.session.add(add_tagtarget)
            db.session.commit()


def add_social_countries(countries,social_id):
    db.session.query(Socialcountrytargets).filter_by(social_id=social_id).delete()
    if len(countries) is not 1:
        try:
            countries.remove("ALL")
            pass
        except ValueError:
            pass

    for country in countries:
        country_info = Countries.query.filter_by(country_code=country.strip()).first()
        add_country = Socialcountrytargets()
        add_country.country_id = country_info.id
        add_country.social_id = social_id
        db.session.add(add_country)
        db.session.commit()


def stringtobool(data):
    if data == 'true':
        return True
    else:
        return False


@login_manager.user_loader
def get_user(ident):
    return Users.query.get(int(ident))


@app.template_filter('aes_encode')
def _jinja2_filter_aes_encode(text):
    result = aes_encode(str(text))
    return result


@app.template_filter('datetime_short')
def _jinja2_filter_datetime(date):
    result = datetime.strftime(date, '%Y-%m-%d %H:%M:%S')
    return result


@app.template_filter('base64_encode')
def _jinja2_filter_base64_encode(text):
    encodedBytes = base64.b64encode(str(text).encode("utf-8"))
    result = str(encodedBytes, "utf-8")
    return result


@app.route('/')
def home():
    country = db.session.query(Countries.id).filter_by(country_code=get_browser_country().upper()).first()
    page = request.args.get('page', 1, type=int)
    socialmedias = db.session.query(Socialmedia.id_share, Socialmedia.author_name, Socialmedia.media_id,
                                   Socialmedia.sponsor, Socialmedia.type).join(Socialcountrytargets,
                                                                               Socialmedia.id == Socialcountrytargets.social_id).filter(
        Socialmedia.delete == False, Socialmedia.disable == False, Socialmedia.verification == True,
        Socialcountrytargets.country_id == country,
        Socialmedia.last_update.between(date_back_to(120), datetime.utcnow())).order_by(desc(Socialmedia.sponsor), desc(
        Socialmedia.last_update)).paginate(page, 15, False)
    next_url = url_for('home', page=socialmedias.next_num) \
        if socialmedias.has_next else None
    prev_url = url_for('home', page=socialmedias.prev_num) \
        if socialmedias.has_prev else None

    pipeline = [
        {"$unwind": "$tag_name"},
        {"$match": {"locale": get_browser_country(), "create_date": {"$gte": date_back_to(360), "$lte": datetime.utcnow()}}},
        {"$group": {"_id": {"tag_id": "$tag_id", "tag_name": "$tag_name"}, "count": {"$sum": 1}}},
        {"$sort": SON([("count", -1), ("_id", -1)])},
        {"$limit": 8}
    ]

    tags = list(Search.aggregate(pipeline))

    return render_template('home.html', socialmedias=socialmedias, next_url=next_url, prev_url=prev_url, tags=tags)


@app.route('/view/<id_share>', methods=['GET'])
def Social(id_share):
    socialmedia_check = SocialMedia.find_one(
        {"id_share": id_share, "delete": False, "disable": False, "verification": True})
    if socialmedia_check is not None:
        if current_user.is_authenticated:
            socialmedia_statistics(current_user.id, socialmedia_check['social_id'], False)
        display = Socialstatistics.query.filter_by(social_id=socialmedia_check['social_id'], clicks=False).count()
        author_image = instagram_profile_image(socialmedia_check['author_name'])
        saved_count = Socialsaved.query.filter_by(social_id=socialmedia_check['social_id']).count()
        if saved_count == 1:
            saved = True
        else:
            saved = False

        tags = Socialtagtargets.query.filter_by(social_id=socialmedia_check['social_id'])
        tags_array = []
        for tag in tags:
            tags_array.append(tag.tag_id)

        supriz_tag = tags_array[randint(0,len(tags_array)-1)]
        similar_product = db.session.query(Socialmedia.id_share, Socialmedia.author_name, Socialmedia.media_image,).join(Socialtagtargets,
                                                                                    Socialmedia.id == Socialtagtargets.social_id).filter(
            Socialmedia.delete == False, Socialmedia.disable == False, Socialmedia.verification == True, Socialmedia.id != socialmedia_check['social_id'],
            Socialtagtargets.tag_id == supriz_tag).order_by(desc(Socialmedia.last_update)).limit(10)

        similar_product_count = similar_product.count()

        return render_template(
            'layout/layout_post.html',
            id_share=socialmedia_check['id_share'],
            author_name=socialmedia_check['author_name'],
            author_image=author_image,
            media_description=socialmedia_check['media_description'],
            media_id=socialmedia_check['media_id'],
            media_url=socialmedia_check['media_url'],
            sponsor=socialmedia_check['sponsor'],
            type=socialmedia_check['type'],
            display=display,
            saved=saved,
            similar_product=similar_product,
            similar_product_count=similar_product_count
        )
    else:
        socialmedia = Socialmedia.query.filter_by(id_share=id_share, delete=False, disable=False,
                                                  verification=True).first()
        if socialmedia is not None:
            if current_user.is_authenticated:
                socialmedia_statistics(current_user.id, socialmedia.id, False)
            display = Socialstatistics.query.filter_by(social_id=socialmedia.id, clicks=False).count()
            author_image = instagram_profile_image(socialmedia.author_name)
            saved_count = Socialsaved.query.filter_by(social_id=socialmedia.id).count()
            if saved_count == 1:
                saved = True
            else:
                saved = False

            tags = Socialtagtargets.query.filter_by(social_id=socialmedia.id)
            tags_array = []
            for tag in tags:
                tags_array.append(tag.tag_id)

            supriz_tag = tags_array[randint(0, len(tags_array) - 1)]
            similar_product = db.session.query(Socialmedia.id_share, Socialmedia.author_name,
                                               Socialmedia.media_image, ).join(Socialtagtargets,
                                                                               Socialmedia.id == Socialtagtargets.social_id).filter(
                Socialmedia.delete == False, Socialmedia.disable == False, Socialmedia.verification == True,
                Socialmedia.id != socialmedia.id,
                Socialtagtargets.tag_id == supriz_tag).order_by(desc(Socialmedia.last_update)).limit(10)

            similar_product_count = similar_product.count()

            SocialMedia.insert_one(
                {"social_id": socialmedia.id,
                 "id_share": socialmedia.id_share,
                 "author_name": socialmedia.author_name,
                 "media_id": socialmedia.media_id,
                 "media_description": socialmedia.media_description,
                 "media_image": socialmedia.media_image,
                 "media_url": socialmedia.media_url,
                 "provider_name": socialmedia.provider_name,
                 "delete": socialmedia.delete,
                 "disable": socialmedia.disable,
                 "verification": socialmedia.verification,
                 "sponsor": socialmedia.sponsor,
                 "type": socialmedia.type,
                 "creation_date": socialmedia.creation_date,
                 "last_update": socialmedia.last_update,
                 "cache_expiration": cache_expiration(72)
                 })

            return render_template(
                'layout/layout_post.html',
                id_share=socialmedia.id_share,
                author_name=socialmedia.author_name,
                author_image=author_image,
                media_description=socialmedia.media_description,
                media_id=socialmedia.media_id,
                media_url=socialmedia.media_url,
                sponsor=socialmedia.sponsor,
                type=socialmedia.type,
                display=display,
                saved=saved,
                similar_product=similar_product,
                similar_product_count=similar_product_count
            )
        else:
            return render_template('layout/layout_post_404.html'), 404


@app.route('/tag')
def tag_list():
    page = request.args.get('page', 1, type=int)
    tag = request.args.get('id', type=int)
    socialmedias = db.session.query(Socialmedia.id_share, Socialmedia.author_name, Socialmedia.media_image,
                                   Socialmedia.sponsor, Socialmedia.type).join(Socialtagtargets,
                                                                               Socialmedia.id == Socialtagtargets.social_id).filter(
        Socialmedia.delete == False, Socialmedia.disable == False, Socialmedia.verification == True,
        Socialtagtargets.tag_id == tag).order_by(
        desc(Socialmedia.sponsor), desc(Socialmedia.last_update)).paginate(page, 15, False)
    next_url = url_for('tag_list', page=socialmedias.next_num) \
        if socialmedias.has_next else None
    prev_url = url_for('tag_list', page=socialmedias.prev_num) \
        if socialmedias.has_prev else None

    pipeline = [
        {"$unwind": "$tag_name"},
        {"$match": {"locale": get_browser_country(), "create_date": {"$gte": date_back_to(360), "$lte": datetime.utcnow()}}},
        {"$group": {"_id": {"tag_id": "$tag_id", "tag_name": "$tag_name"}, "count": {"$sum": 1}}},
        {"$sort": SON([("count", -1), ("_id", -1)])},
        {"$limit": 8}
    ]

    tags = list(Search.aggregate(pipeline))

    if current_user.is_authenticated:
        if len(socialmedias.items) > 0:
            if page == 1:
                tag_search = Tags.query.filter_by(id=tag).first()
                Search.insert_one(
                    {"tag_id": tag_search.id,
                     "tag_name": tag_search.tag_name,
                     "locale": get_browser_country(),
                     "user_id": current_user.id,
                     "create_date": datetime.utcnow()
                     })

    return render_template('tag.html', socialmedias=socialmedias, next_url=next_url, prev_url=prev_url, tags=tags, tag_id=tag)


@app.route('/add')
@login_required
def add_product():
    return render_template('add_product.html')


@app.route('/add', methods=['POST'])
@login_required
def add_product_post():
    media_url = request.form['link']
    tags = request.form['tags']
    countries = request.form['countries']
    product_type = request.form['type']

    tags = tags.replace('[', '')
    tags = tags.replace(']', '')
    countries = countries.replace('[', '')
    countries = countries.replace(']', '')
    tags = tags.split(',')
    countries = countries.split(',')

    while ('' in tags):
        tags.remove('')

    while ('' in countries):
        countries.remove('')

    if len(tags) < 2:
        return jsonify(api_result=gettext('at_least_two_labels_must_be_entered'), status=False)
    elif len(tags) > 4:
        return jsonify(api_result=gettext('up_to_four_labels_must_be_entered'), api_status=False)
    elif len(countries) == 0:
        return jsonify(api_result=gettext('At_least_one_country_must_be_selected'), api_status=False)
    elif len(countries) > 10:
        return jsonify(api_result=gettext('Up_to_ten_countries_must_be_selected'), api_status=False)
    elif media_url == '':
        return jsonify(api_result=gettext('url_cannot_be_empty'), api_status=False)
    elif product_type == 'null':
        return jsonify(api_result=gettext('select_product_type'), api_status=False)
    else:
        parse = urlparse(media_url)
        media_url = "https://"+parse.netloc+parse.path
        if parse.netloc == "www.instagram.com" or parse.netloc == "instagram.com":
            try:
                with urllib.request.urlopen("https://api.instagram.com/oembed/?url=" + media_url) as url:
                    data = json.loads(url.read().decode())
                    media_shortcode = parse.path.replace('p', '', 1)
                    media_shortcode = media_shortcode.replace('/', '')
                    socialmedia = Socialmedia.query.filter_by(media_id=data["media_id"]).first()
                    if socialmedia is not None:
                        return jsonify(api_status=False, api_result="raffle added")
                    else:
                        socialmedia = Socialmedia()
                        socialmedia.id_share = uuid_short()
                        socialmedia.author_name = data["author_name"]
                        socialmedia.media_id = media_shortcode
                        socialmedia.media_description = data["title"]
                        socialmedia.media_image = 'https://instagram.com/p/'+media_shortcode+'/media/?size=l'
                        socialmedia.media_url = media_url
                        socialmedia.provider_name = data["provider_name"]
                        socialmedia.delete = False
                        socialmedia.disable = False
                        socialmedia.verification = True
                        socialmedia.sponsor = False
                        socialmedia.type = stringtobool(type)
                        socialmedia.creation_date = datetime.utcnow()
                        socialmedia.last_update = datetime.utcnow()
                        db.session.add(socialmedia)
                        db.session.commit()
                        add_social_tags(tags, socialmedia.id)
                        add_social_countries(countries, socialmedia.id)
                        return jsonify(api_status=True, api_result=gettext('The_product_has_been_sent'))
            except ValueError:
                return jsonify(api_status=False, api_result=gettext('404_not_found'))
        else:
            return jsonify(api_status=False, api_result=gettext('invalid_url'))


@app.route('/search', methods=['POST'])
def tag_search():
    query = request.form['query']
    if len(query) >= 2:
        tags = Tags.query.filter(Tags.tag_name.like(query+'%')).limit(10)
        return render_template('tag_search.html', tags=tags)
    else:
        tags = 0
        return render_template('tag_search.html',tags=tags)


@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(session_get_redirect())
    google = get_google_auth()
    auth_url, state = google.authorization_url(
        Auth.AUTH_URI, access_type='offline')
    session['oauth_state'] = state
    session_id_create()
    redirect_to = request.args.get('redirect')
    if redirect_to is not None:
        session['redirect'] = redirect_to
    return render_template('login.html', auth_url=auth_url)


@app.route('/logout')
@login_required
def logout():
    add_log("logout", None)
    logout_user()
    return redirect(url_for('home'))


@app.route('/gCallback')
def callback():
    # Redirect user to home page if already logged in.
    if current_user is not None and current_user.is_authenticated:
        return redirect(url_for('home'))
    if 'error' in request.args:
        if request.args.get('error') == 'access_denied':
            return 'You denied access.'
        return 'Error encountered.'
    if 'code' not in request.args and 'state' not in request.args:
        return redirect(url_for('login'))
    else:
        # Execution reaches here when user has
        # successfully authenticated our app.
        google = get_google_auth(state=session['oauth_state'])
        try:
            token = google.fetch_token(
                Auth.TOKEN_URI,
                client_secret=Auth.CLIENT_SECRET,
                authorization_response=request.url)
        except HTTPError:
            return 'HTTPError occurred.'
        google = get_google_auth(token=token)
        resp = google.get(Auth.USER_INFO)
        if resp.status_code == 200:
            user_data = resp.json()
            email = user_data['email']
            provider_id = user_data['id']
            user = Users.query.filter_by(mail_adress=email).filter_by(provider_id=provider_id).first()
            if user is None:
                user = Users()
                user.provider_name = 'google'
                user.provider_id = user_data['id']
                user.mail_adress = user_data['email']
                user.name = user_data['name']
                user.local = user_data['locale']
                user.profile_picture = user_data['picture']
                user.id_share = uuid_short()
                user.is_active = True
                user.creation_date = datetime.utcnow()
                user.last_update = datetime.utcnow()
                db.session.add(user)
                db.session.commit()
                login_user(user)
                add_log("login", None)
                return redirect(session_get_redirect())
            else:
                user_up = Users.query.filter_by(mail_adress=email).filter_by(provider_id=provider_id).first()
                user_up.last_update = datetime.utcnow()
                user_up.profile_picture = user_data['picture']
                user_up.local = user_data['locale']
                db.session.add(user_up)
                db.session.commit()
                login_user(user)
                add_log("login", None)
                return redirect(session_get_redirect())
        return 'Could not fetch your information.'


@app.route('/share/<id_share>', methods=['GET'])
def Share(id_share):
    raffle = Raffles.query.filter_by(id_share=id_share).filter_by(delete=False).filter_by(disable=False).first()
    if raffle is not None:
        raffle_join_count = Participants.query.filter_by(raffle_id=raffle.id).count()
        tags = db.session.query(Tags.tag_name).join(Tagtargets, Tags.id == Tagtargets.tag_id).filter(
            Tagtargets.raffle_id == raffle.id).all()
        qr_code = id_share
        id_share = aes_encode(id_share)
        if current_user.is_authenticated:
            user_raffle_join_count = Participants.query.filter_by(user_id=current_user.id).filter_by(raffle_id=raffle.id).count()
        else:
            user_raffle_join_count = 0
        return render_template('share.html',raffle=raffle,user_raffle_join_count=user_raffle_join_count,raffle_join_count=raffle_join_count,id_share=id_share,qr_code=qr_code,tags=tags)
    else:
        return render_template('share_404.html'), 404


@app.route('/widget/<id_share>', methods=['GET'])
def Widget(id_share):
    raffle = Raffles.query.filter_by(id_share=id_share).filter_by(delete=False).filter_by(disable=False).first()
    if raffle is not None:
        raffle_join_count = Participants.query.filter_by(raffle_id=raffle.id).count()
        tags = db.session.query(Tags.tag_name).join(Tagtargets, Tags.id == Tagtargets.tag_id).filter(
            Tagtargets.raffle_id == raffle.id).all()
        qr_code = id_share
        id_share = aes_encode(id_share)
        if current_user.is_authenticated:
            user_raffle_join_count = Participants.query.filter_by(user_id=current_user.id).filter_by(raffle_id=raffle.id).count()
        else:
            user_raffle_join_count = 0
        return render_template('widget.html',raffle=raffle,user_raffle_join_count=user_raffle_join_count,raffle_join_count=raffle_join_count,id_share=id_share,qr_code=qr_code,tags=tags)
    else:
        return render_template('widget_404.html'), 404


@app.route('/SweepstakesManage')
@login_required
def sweepstakesmanage():
    page = request.args.get('page', 1, type=int)
    raffles = db.session.query(Raffles.id_share,Raffles.title,Raffles.creation_date,Raffles.last_update,Raffles.status,Raffles.completed).filter_by(user_id=current_user.id).filter_by(delete=False).filter_by(disable=False).order_by(desc(Raffles.id)).paginate(page, 15, False)
    next_url = url_for('sweepstakesmanage', page=raffles.next_num) \
        if raffles.has_next else None
    prev_url = url_for('sweepstakesmanage', page=raffles.prev_num) \
        if raffles.has_prev else None
    return render_template('sweepstakesmanage.html',raffles=raffles,next_url=next_url, prev_url=prev_url)


@app.route('/CreateRaffle', methods=['POST'])
@login_required
def create_raffle():
    tags = request.form['tags']
    tags = tags.split(',')
    countries = request.form['countries']
    countries = countries.split(',')
    title = request.form['title']
    description = request.form['description']
    expiration = request.form['expiration']
    winners = request.form['winners']
    reserves = request.form['reserves']
    contact_information = request.form['contact_information']
    if title.strip() is "":
        return jsonify(result=gettext("the_title_cannot_be_blank"),status=False)
    elif description.strip() is "":
        return jsonify(result=gettext("description_cannot_be_left_blank"),status=False)
    elif description.strip() is "":
        return jsonify(result=gettext("contact_information_cannot_be_blank"),status=False)
    elif expiration.strip() is "":
        return jsonify(result=gettext("end_date_cannot_be_blank"),status=False)
    elif winners.strip() is "":
        return jsonify(result=gettext("the_number_of_winners_cannot_be_blank"), status=False)
    elif reserves.strip() is "":
        return jsonify(result=gettext("the_number_of_replacement_people_cannot_be_blank"), status=False)
    elif int(winners) <= 0:
        return jsonify(result=gettext("the_number_of_people_to_win_cannot_be_less_than_zero_or_zero"),status=False)
    elif int(reserves) < 0:
        return jsonify(result=gettext("the_number_of_backup_contacts_cannot_be_less_than_zero"), status=False)
    elif int(len(title)) > 60:
        return jsonify(result=gettext("the_title_cannot_be_greater_than_60_characters"), status=False)
    elif int(len(description)) > 350:
        return jsonify(result=gettext("the_description_cannot_be_greater_than_350_characters"), status=False)
    elif int(len(contact_information)) > 350:
        return jsonify(result=gettext("contact_information_cannot_be_greater_than_350_characters"), status=False)
    elif int(winners) > 50:
        return jsonify(result=gettext("the_number_of_people_who_will_win_can_not_be_more_than_50"),status=False)
    elif int(reserves) > 50:
        return jsonify(result=gettext("the_number_of_reserve_persons_cannot_be_more_than_50"), status=False)
    elif len(tags) < 2:
        return jsonify(result=gettext("at_least_two_labels_must_be_entered"), status=False)
    elif len(tags) > 4:
        return jsonify(result=gettext("up_to_four_labels_must_be_entered"), status=False)
    elif countries[0].strip() is "":
        return jsonify(result=gettext('At_least_one_country_must_be_selected'), status=False)
    elif len(countries) > 10:
        return jsonify(result=gettext('Up_to_ten_countries_must_be_selected'), status=False)
    else:
        raffle = Raffles()
        raffle.title = title
        raffle.description = description
        raffle.contact_information = contact_information
        raffle.expiration = expiration
        raffle.id_share = uuid_short()
        raffle.status = False
        raffle.processing = False
        raffle.completed = False
        raffle.delete = False
        raffle.disable = False
        raffle.winners = winners
        raffle.reserves = reserves
        raffle.user_id = current_user.id
        raffle.creation_date = datetime.utcnow()
        raffle.last_update = datetime.utcnow()
        raffle.raffle_date = datetime.utcnow()
        db.session.add(raffle)
        db.session.commit()
        add_tags(tags, raffle.id)
        add_countries(countries,raffle.id)
        add_log("raffle_created", json.dumps({"raffle_id": raffle.id}))
        return jsonify(result=gettext("raffle_created"),status=True)


@app.route('/JoinRaffle', methods=['POST'])
@login_required
def joinraffle():
        id_share = aes_decode(request.form['id'])
        raffle = Raffles.query.filter_by(id_share=id_share).first()
        raffle_join_count = Participants.query.filter_by(user_id=current_user.id).filter_by(raffle_id=raffle.id).count()
        if raffle is None:
            return jsonify(result=gettext("no_raffles_found"), status=False)
        elif raffle.delete is True:
            return jsonify(result=gettext("no_attendance_for_the_raffle_was_deleted"), status=False)
        elif raffle.disable is True:
            return jsonify(result=gettext("raffle_disabled"), status=False)
        elif raffle.expiration < datetime.utcnow():
            return jsonify(result=gettext("ended_participation"), status=False)
        elif raffle.user_id is current_user.id:
            return jsonify(result=gettext("you_cant_participate_in_your_own_lottery"), status=False)
        elif raffle_join_count > 0:
            return jsonify(result=gettext("you_ve_already_joined"), status=False)
        elif raffle_check_country(raffle.id) is False:
            return jsonify(result=gettext('Is_unavailable_in_your_country'), status=False)
        else:
            participant = Participants()
            participant.user_id = current_user.id
            participant.raffle_id = raffle.id
            participant.date = datetime.strftime(datetime.utcnow(), '%Y-%m-%d')
            participant.creation_date = datetime.utcnow()
            db.session.add(participant)
            db.session.commit()
            add_log("you_took_the_lottery", json.dumps({"raffle_id": raffle.id, "raffle_share": raffle.id_share}))
            return jsonify(result=gettext("you_took_the_lottery"), status=True)


@app.route('/RaffleShow', methods=['POST'])
@login_required
def raffleshow():
        id_share = aes_decode(request.form['id'])
        raffle = Raffles.query.filter_by(id_share=id_share).filter_by(user_id=current_user.id).filter_by(delete=False).filter_by(disable=False).first()
        if raffle is not None:
            raffle_join_count = Participants.query.filter_by(raffle_id=raffle.id).count()
            tags = db.session.query(Tags.tag_name).join(Tagtargets, Tags.id == Tagtargets.tag_id).filter(
                Tagtargets.raffle_id == raffle.id).all()
            raffle_tag = []
            for tag in tags:
                item = {}
                item['text'] = str(tag[0])
                item['value'] = str(tag[0])
                raffle_tag.append(item)
            countries_selected = db.session.query(Countries.country_code).join(Countrytargets,
                                                                               Countries.id == Countrytargets.country_id).filter(
                Countrytargets.raffle_id == raffle.id).all()
            last_update = datetime.strftime(raffle.last_update, '%Y-%m-%d %H:%M:%S')
            return jsonify(id=aes_encode(raffle.id_share), title=raffle.title, description=raffle.description,
                           contact_information=raffle.contact_information, expiration=str(raffle.expiration),
                           winners=raffle.winners, reserves=raffle.reserves, raffle_join_count=raffle_join_count,
                           status=raffle.status, tags=raffle_tag, countries_selected=countries_selected)
        else:
            return jsonify(result=gettext("no_raffles_found"), status=False)


@app.route('/RaffleUpdate', methods=['POST'])
@login_required
def raffleupdate():
    id_share = aes_decode(request.form['id'])
    raffle = Raffles.query.filter_by(id_share=id_share).filter_by(user_id=current_user.id).first()
    tags = request.form['tags']
    tags = tags.split(',')
    countries = request.form['countries']
    countries = countries.split(',')
    title = request.form['title']
    description = request.form['description']
    contact_information = request.form['contact_information']
    expiration = request.form['expiration']
    winners = request.form['winners']
    reserves = request.form['reserves']
    if title.strip() is "":
        return jsonify(result=gettext("the_title_cannot_be_blank"),status=False)
    elif description.strip() is "":
        return jsonify(result=gettext("description_cannot_be_left_blank"),status=False)
    elif contact_information.strip() is "":
        return jsonify(result=gettext("contact_information_cannot_be_blank"),status=False)
    elif expiration.strip() is "":
        return jsonify(result=gettext("end_date_cannot_be_blank"),status=False)
    elif winners.strip() is "":
        return jsonify(result=gettext("the_number_of_winners_cannot_be_blank"), status=False)
    elif reserves.strip() is "":
        return jsonify(result=gettext("the_number_of_replacement_people_cannot_be_blank"), status=False)
    elif int(winners) <= 0:
        return jsonify(result=gettext("the_number_of_people_to_win_cannot_be_less_than_zero_or_zero"),status=False)
    elif int(reserves) < 0:
        return jsonify(result=gettext("the_number_of_backup_contacts_cannot_be_less_than_zero"), status=False)
    elif int(len(title)) > 60:
        return jsonify(result=gettext("the_title_cannot_be_greater_than_60_characters"), status=False)
    elif int(len(description)) > 350:
        return jsonify(result=gettext("the_description_cannot_be_greater_than_350_characters"), status=False)
    elif int(len(contact_information)) > 350:
        return jsonify(result=gettext("contact_information_cannot_be_greater_than_350_characters"), status=False)
    elif int(winners) > 50:
        return jsonify(result=gettext("the_number_of_people_who_will_win_can_not_be_more_than_50"),status=False)
    elif int(reserves) > 50:
        return jsonify(result=gettext("the_number_of_reserve_persons_cannot_be_more_than_50"), status=False)
    elif raffle.status is True:
        return jsonify(result=gettext("the_lottery_doesnt_update_because_it_started"), status=False)
    elif raffle.delete is True:
        return jsonify(result=gettext("raffle_deleted_update_failed"), status=False)
    elif raffle.disable is True:
        return jsonify(result=gettext("raffle_disabled"), status=False)
    elif len(tags) < 2:
        return jsonify(result=gettext("at_least_two_labels_must_be_entered"), status=False)
    elif len(tags) > 4:
        return jsonify(result=gettext("up_to_four_labels_must_be_entered"), status=False)
    elif countries[0].strip() is "":
        return jsonify(result=gettext('At_least_one_country_must_be_selected'), status=False)
    elif len(countries) > 10:
        return jsonify(result=gettext('Up_to_ten_countries_must_be_selected'), status=False)
    else:
        raffle.title = title
        raffle.description = description
        raffle.contact_information = contact_information
        raffle.expiration = expiration
        raffle.winners = winners
        raffle.reserves = reserves
        raffle.last_update = datetime.utcnow()
        db.session.add(raffle)
        db.session.commit()
        add_tags(tags, raffle.id)
        add_countries(countries, raffle.id)
        add_log("raffle_updated", json.dumps({"raffle_id": raffle.id, "raffle_share": raffle.id_share}))
        return jsonify(result=gettext("raffle_updated"),status=True)


@app.route('/RaffleStats', methods=['POST'])
@login_required
def rafflestats():
    id_share = aes_decode(request.form['id'])
    raffle = Raffles.query.filter_by(id_share=id_share).filter_by(user_id=current_user.id).filter_by(delete=False).filter_by(disable=False).first()
    if raffle is not None:
        stats = db.session.query(func.date(Participants.date).label("year"),func.count(Participants.id).label("value")).filter_by(raffle_id=raffle.id).group_by(Participants.date).order_by(desc(Participants.date)).limit(10)
        data = []
        for stat in stats:
            item = {}
            item["year"] = str(stat.year)
            item["value"] = stat.value
            data.append(item)
        return jsonify(data)
    else:
        data = []
        item = {}
        item["year"] = str(datetime.utcnow())
        item["value"] = '0'
        data.append(item)
        return jsonify(data)


@app.route('/RaffleStart', methods=['POST'])
@login_required
def rafflestart():
    id_share = aes_decode(request.form['id'])
    raffle = Raffles.query.filter_by(id_share=id_share).filter_by(user_id=current_user.id).first()
    raffle_count = Participants.query.filter_by(raffle_id=raffle.id).count()
    total = raffle.winners + raffle.reserves
    if int(raffle_count) == 0:
        return jsonify(result=gettext("sufficient_participants_could_not_be_provided"),status=False)
    elif int(raffle_count) <= int(total):
        return jsonify(result=gettext("sufficient_participants_could_not_be_provided"), status=False)
    elif raffle.status is True:
        return jsonify(result=gettext("the_raffle_has_already_started"), status=False)
    elif raffle.delete is True:
        return jsonify(result=gettext("cannot_start_because_the_raffle_was_deleted"), status=False)
    elif raffle.disable is True:
        return jsonify(result=gettext("raffle_disabled"), status=False)
    else:
        raffle = Raffles.query.filter_by(id_share=id_share).filter_by(user_id=current_user.id).first()
        raffle.raffle_date = datetime.utcnow() + timedelta(minutes=10)
        raffle.last_update = datetime.utcnow()
        raffle.status = True
        db.session.add(raffle)
        db.session.commit()
        add_log("the_raffle_starts_in_minutes", None)
        return jsonify(result=gettext("the_raffle_starts_in_minutes"),status=True)


@app.route('/RaffleDelete', methods=['POST'])
@login_required
def raffledelete():
    id_share = aes_decode(request.form['id'])
    raffle = Raffles.query.filter_by(id_share=id_share).filter_by(user_id=current_user.id).first()
    if raffle.delete is True:
        return jsonify(result=gettext("your_deletion_request_has_already_been_received"),status=False)
    elif raffle.status is True:
        return jsonify(result=gettext("could_not_be_deleted_because_the_lottery_was_started"), status=False)
    elif raffle.disable is True:
        return jsonify(result=gettext("raffle_disabled"), status=False)
    else:
        raffle = Raffles.query.filter_by(id_share=id_share).filter_by(user_id=current_user.id).first()
        raffle.last_update = datetime.utcnow()
        raffle.delete = True
        db.session.add(raffle)
        db.session.commit()
        add_log("your_request_for_deletion_has_been_received", json.dumps({"raffle_id": raffle.id, "raffle_share": raffle.id_share, "raffle_title": raffle.title}))
        return jsonify(result=gettext("your_request_for_deletion_has_been_received"),status=True)


@app.route('/RaffleResult', methods=['POST'])
@login_required
def raffleresult():
    id_share = aes_decode(request.form['id'])
    raffle = Raffles.query.filter_by(id_share=id_share).filter_by(completed=True).filter_by(delete=False).filter_by(disable=False).filter_by(user_id=current_user.id).first()
    if raffle is not None:
        winners = db.session.query(Users.name,Luckys.status,Luckys.check_key,Users.id_share).join(Luckys,Users.id == Luckys.user_id).filter_by(raffles_id=raffle.id).filter_by(status=True).all()
        reserves = db.session.query(Users.name,Luckys.status,Luckys.check_key,Users.id_share).join(Luckys,Users.id == Luckys.user_id).filter_by(raffles_id=raffle.id).filter_by(status=False).all()
        return render_template('raffleresult.html',winners=winners,reserves=reserves,id_share=raffle.id_share)
    else:
        return render_template('raffleresult_404.html')


@app.route('/RaffleSecretKeyCheck', methods=['POST'])
@login_required
def rafflesecretkeycheck():
    id_share = aes_decode(request.form['id'])
    secretkey = request.form['secretkey']
    raffle = Raffles.query.filter_by(id_share=id_share).filter_by(completed=True).filter_by(user_id=current_user.id).filter_by(delete=False).filter_by(disable=False).first()
    if raffle is not None:
        result = db.session.query(Users.name, Luckys.status, Users.id_share).join(Luckys,Users.id == Luckys.user_id).filter_by(secret_key=secretkey).first()
        if result is not None:
            lucky_key_check = Luckys.query.filter_by(secret_key=secretkey).first()
            lucky_key_check.check_key = True
            db.session.add(lucky_key_check)
            db.session.commit()
            return jsonify(name=result.name,status=result.status,id=result.id_share)
        else:
            return jsonify(result=gettext("no_contact_found"),error=True)
    return jsonify(result=gettext("no_raffles_found"),error=True)


@app.route('/RaffleCountriesList', methods=['POST'])
@login_required
def rafflecountrieslist():
    countries = db.session.query(Countries.country_code, Countrymultilang.country_name).join(Countrymultilang,Countries.country_code == Countrymultilang.country_code).filter_by(multi_code=get_locale()).order_by(Countrymultilang.country_name).all()
    data = []
    for country in countries:
        item = {}
        item["value"] = country.country_code
        item["text"] = country.country_name
        data.append(item)
    return jsonify(data)


@app.route('/ListMyParticipations')
@login_required
def listmyparticipations():
    page = request.args.get('page', 1, type=int)
    raffles = db.session.query(Raffles.id_share,Raffles.title,Participants.creation_date,Raffles.completed).join(Participants, Raffles.id == Participants.raffle_id).filter_by(user_id=current_user.id).filter(Raffles.delete==False).filter(Raffles.disable==False).order_by(desc(Participants.creation_date)).paginate(page, 15, False)
    next_url = url_for('listmyparticipations', page=raffles.next_num) \
        if raffles.has_next else None
    prev_url = url_for('listmyparticipations', page=raffles.prev_num) \
        if raffles.has_prev else None
    return render_template('listmyparticipations.html',raffles=raffles,next_url=next_url, prev_url=prev_url)


@app.route('/MyRaffleResult', methods=['POST'])
@login_required
def myraffleresult():
    id_share = aes_decode(request.form['id'])
    raffle = Raffles.query.filter_by(id_share=id_share).filter_by(disable=False).filter_by(delete=False).filter_by(completed=True).first()
    if raffle is not None:
        my_lucky_information = Luckys.query.filter_by(raffles_id=raffle.id).filter_by(user_id=current_user.id).first()
        winners = db.session.query(Users.name,Users.name,Luckys.status,Luckys.check_key,Users.id_share).join(Luckys,Users.id == Luckys.user_id).filter_by(raffles_id=raffle.id).filter_by(status=True).all()
        reserves = db.session.query(Users.name, Users.name, Luckys.status,Luckys.check_key,Users.id_share).join(Luckys,Users.id == Luckys.user_id).filter_by(raffles_id=raffle.id).filter_by(status=False).all()
        if my_lucky_information is not None:
            return render_template('myraffleresult.html',winners=winners,reserves=reserves,secret_key=my_lucky_information.secret_key,contact_information=raffle.contact_information)
        else:
            return render_template('myraffleresult.html', winners=winners, reserves=reserves)
    else:
        return render_template('myraffleresult_404.html')


@app.route('/Feedback', methods=['POST'])
@login_required
def feedback():
    description = request.form['description']
    if description.strip() == "":
        return jsonify(result=gettext("feedback_cant_be_left_blank"),status=False)
    elif len(description) > 350:
        return jsonify(result=gettext("the_feedback_cannot_be_more_than_350_characters"), status=False)
    else:
        create_feedback = Feedbacks()
        create_feedback.description = description
        create_feedback.user_id = current_user.id
        create_feedback.read = False
        create_feedback.creation_date = datetime.utcnow()
        create_feedback.last_update = datetime.utcnow()
        db.session.add(create_feedback)
        db.session.commit()
        add_log("send", None)
        return jsonify(result=gettext("send"),status=True)


@app.route('/Search', methods=['GET'])
@login_required
def search():
    query = request.args.get("q", "")
    page = request.args.get('page', 1, type=int)
    raffles = db.session.query(Raffles.id_share, Raffles.title, Raffles.creation_date).filter_by(id_share=query).filter_by(
        delete=False).filter_by(disable=False).order_by(desc(Raffles.id)).paginate(page, 15, False)
    next_url = url_for('search', page=raffles.next_num) \
        if raffles.has_next else None
    prev_url = url_for('search', page=raffles.prev_num) \
        if raffles.has_prev else None
    return render_template('search.html', raffles=raffles, next_url=next_url, prev_url=prev_url)


@app.route('/AccountDetails')
@login_required
def accountdetails():
    page = request.args.get('page', 1, type=int)
    logs = db.session.query(Logs.action,Logs.ip_address,Logs.creation_date).filter_by(user_id=current_user.id).order_by(desc(Logs.id)).paginate(page, 15, False)
    next_url = url_for('accountdetails', page=logs.next_num) \
        if logs.has_next else None
    prev_url = url_for('accountdetails', page=logs.prev_num) \
        if logs.has_prev else None
    return render_template('accountdetails.html',logs=logs,next_url=next_url, prev_url=prev_url)


@app.route('/QrcodeLogin', methods=['POST'])
def qrcodelogin():
    if current_user.is_authenticated:
        return jsonify(status=True)
    qrcode = Qrcode.query.filter(Qrcode.expiration > datetime.utcnow()).filter_by(status=False).filter_by(key=str(session['id'])).first()
    if qrcode is not None:
        user = Users.query.filter_by(id=qrcode.user_id).first()
        login_user(user)
        qrcode_update = qrcode
        qrcode_update.expiration = datetime.utcnow()
        qrcode_update.status = True
        db.session.add(qrcode_update)
        db.session.commit()
        add_log("QR_code_was_used", None)
        return jsonify(status=True)
    else:
        return jsonify(status=False)


@app.route('/Bgimage')
def bgimage():
    with urllib.request.urlopen("https://www.bing.com/HPImageArchive.aspx?format=js&idx=0&n=1&mkt=en-US") as url:
        data = json.loads(url.read().decode())
    data = "https://www.bing.com"+data["images"][0]["url"]
    return jsonify(image_url=data)


@app.route('/PrivacyPolicy')
def privacypolicy():
    return render_template('privacypolicy.html')


@app.route('/app-ads.txt')
def appads():
    return render_template('app_ads.html')


if __name__ == '__main__':
    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ctx.load_cert_chain('localhost.cert', 'localhost.key')
    app.run(host='127.0.0.1', port=5000, ssl_context=ctx, threaded=True, debug=True)
