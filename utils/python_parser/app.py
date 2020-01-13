from flask import Flask, render_template, request, redirect
from werkzeug.utils import secure_filename
from logging import getLogger
from chipsec_parser import *
from jinja2 import *
import tempfile
import os
import random

app = Flask(__name__)
logger = getLogger("ChipsecParser")
env = Environment(loader=FileSystemLoader('templates'),autoescape=select_autoescape(['html']))
upload_template = env.get_template("report.html")

def parse_file(f):
        save_path = os.path.join(tempfile.gettempdir(),secure_filename(f.filename) + str(random.randint(2**63,2**64)))
        f.save(save_path)
        suite_data, case_data = parse_chipsec_xml(save_path)
        os.unlink(save_path)
        return suite_data, case_data


@app.route('/', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        f = request.files['file']
        suite_data, case_data = parse_file(f)
        return render_template('report.html',suite=suite_data, cases=case_data)
        
    else:
        return render_template('upload.html')

@app.route("/healthz")
def healthz():
    return "{}",200 


