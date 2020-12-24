from flask import Flask
from flask import render_template,request
import subprocess,re
app = Flask(__name__)

@app.route('/',methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/run',methods=['POST'])
def run():
    cmd = request.form.get("cmd")
    if re.search(r'''[^0-9a-zA-Z">\\\$();]''',cmd):
        return 'Hacker!'
    if re.search(r'''ping|wget|curl|bash|perl|python|php|kill|ps''',cmd):
        return 'Hacker!'
    p = subprocess.Popen(cmd,stderr=subprocess.STDOUT, stdout=subprocess.PIPE,shell=True,close_fds=True)
    try:
        (msg, errs) = p.communicate(timeout=5)
        return msg
    except Exception as e:
        return 'Error!'

app.run(host='0.0.0.0',port='5000')