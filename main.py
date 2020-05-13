from flask import Flask,jsonify,abort,make_response,json, render_template, request, flash, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import Form
from wtforms import TextField, SubmitField, TextAreaField
from wtforms.validators import Length, Email, Required

from attack_search import Attack
import json
import os

app = Flask(__name__)
Bootstrap(app)

class JsonForm(Form):
    textArea = TextAreaField('Result', render_kw={'readonly': True})



@app.route('/')
def index():
    form = JsonForm(request.form)

    return render_template('index.html', form=form)

@app.route('/api', methods=['GET', 'POST'])
def api():
    keyword = request.form['keyword']
    form = JsonForm(request.form)

    # if there is data that searched before.
    if os.path.isfile('./bundles/{0}-bundle.json'.format(keyword)):
        with open('./bundles/{0}-bundle.json'.format(keyword)) as f:
            return render_template('index.html', form=form, data=f.readlines()[0])

    else:
        attack = Attack()
        attack_json = attack.get_bundle_json(keyword)


    return render_template('index.html', form=form,  data=attack_json)


@app.route('/group', methods=['GET', 'POST'])
def grouping():
    return 'group'

@app.route('/killchain', methods=['GET', 'POST'])
def killchain():
    return 'killchain'

if __name__=='__main__':
    app.config.from_object(__name__)
    app.config['SECRET_KEY'] = 'tnarudhkTejsskdml~'
    app.run('0.0.0.0',port=1994, debug=True)


