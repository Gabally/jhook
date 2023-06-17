import telebot
from os import getenv
from .models import *
from threading import Thread
import sys

def messageworker(bot, q):
    while True:
        try:
            msg = q.get(block=True)
            bot.send_message(msg["chat"], msg["text"])
        except Exception as e:
            print("Exception while sending telegram message:")
            print(e)

def botProcess(app, q, botKey):
    if botKey is None:
        sys.exit("[!] Missing bot api key (telegram notification functionality will be disabled)")
    bot = telebot.TeleBot(botKey)
    Thread(target=messageworker, args=(bot,q)).start()

    @bot.message_handler(commands=['register'])
    def send_confirmation(message):
        with app.app_context():
            if (TelegramUsers.query.filter_by(chatID=message.from_user.id).first() is None):
                db.session.add(TelegramUsers(name=message.from_user.username if (message.from_user.username != None) else " ".join([message.from_user.first_name, message.from_user.last_name]), chatID=message.from_user.id, approved=None))
                db.session.commit()
                bot.reply_to(message, "Regsitration request received")
            db.session.close()
            
    bot.infinity_polling()