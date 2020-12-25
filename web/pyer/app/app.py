#! /usr/bin/env python
#encoding=utf-8
from flask import Flask,render_template,redirect,session
#from flask_login import login_required,LoginManager
from flask import request
#from model import login_manager
import urllib
import sys
import os
from jinja2 import Template
import sqlite3

app = Flask(__name__)
app.secret_key = 'b1ind123!@#'

@app.route("/", methods=['GET'])
def index():
    return redirect('/login')

@app.route("/login", methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        sql = "select password from users where username='" + username + "'"
        conn = sqlite3.connect('test.db')
        c = conn.cursor()
        cursor = c.execute(sql)
        flag = 0
        for row in cursor:
            if(not len(row)):
                flag = 0
            else:
                if row[0] == password:
                    flag = 1
            break
        conn.close()
        if flag == 1:
            session['user'] = request.form.get('username')
        else:
            return render_template("error.html",error="login error")
        return redirect('/admin')

@app.route("/admin", methods=['GET','POST'])
def admin():
    if not session:
        return redirect('/login')
    if request.method == 'GET':
        return render_template('admin.html')
    if request.method == 'POST':
        if session['user'] != 'admin':
            return render_template("error.html",error="you are not admin")
        username = request.form.get('username')
        sql = "select comment from comment where username = '" + username + "'"
        conn = sqlite3.connect('test.db')
        c = conn.cursor()
        cursor = c.execute(sql)
        for row in cursor:
            if len(row):
                f = open('templates/admin.html','r', encoding='utf-8')
                comment = "<h1>" + row[0] + "</h1>"
                content = f.read().replace("<!--hello ctfer-->",comment)
                f.close()
                t = Template(content)
            else:
                f = open('templates/admin.html','r', encoding='utf-8')
                comment = "<h1>no comment</h1>"
                content = f.read().replace("<!--hello ctfer-->",comment)
                f.close()
                t = Template(content)
            conn.close()
            return t.render()
        f = open('templates/admin.html','r', encoding='utf-8')
        comment = "<h1>no comment</h1>"
        content = f.read().replace("<!--hello ctfer-->",comment)
        f.close()
        t = Template(content)
        return t.render()


if __name__ == '__main__':
    app.debug = False
    app.run(host='0.0.0.0', port=8000)
