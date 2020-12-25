#! /usr/bin/env python
#encoding=utf-8
from flask import Flask,render_template,redirect
from flask import request
import urllib
import sys
import os
from jinja2 import Template

app = Flask(__name__)

def safe_msg(msg):
    blacklist = ['~','set','or','args','_','[','request','lipsum','=','chr','json','g','.',"'",'{{','u','get',' ',',','*','^','&','$','#','@','!']
    for i in blacklist:
        if i in msg: 
            return False
    return True

@app.route("/", methods=['GET'])
def index():
    return render_template("index.html")


@app.route("/over", methods=['GET'])
def over():
    return render_template('over.html')


@app.route("/success", methods=['GET'])
def success():
    msg = request.args.get("msg")
    if(msg == None):
        msg = 'anonymous'
    if safe_msg(msg):
        t = Template("Good Job! " + msg + " . But sorry, there isn't flag")
    else:
        t = Template("You look dangerous.....")
    return t.render(request=request)


if __name__ == '__main__':
    app.debug = False
    app.run(host='0.0.0.0', port=8000)
