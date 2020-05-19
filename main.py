from flask import Flask,jsonify,abort,make_response,json, render_template, request, flash, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import Form as BaseForm
from wtforms import TextField, SubmitField, TextAreaField
from wtforms.validators import Length, Email, DataRequired,EqualTo
from flask_wtf.csrf import CSRFProtect
from attack_search import Attack
from grouping import make_group
import json
import os

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
Bootstrap(app)
csrf = CSRFProtect(app)

class JsonForm(BaseForm):
    textArea = TextAreaField('Object json', validators=[Length(min=1,message='HEY!')] ,render_kw={'readonly': True, 'id':'result', 'style':'height: 800px;', 'placeholder':'Related object will present here.'})



@app.route('/')
def index():
    form = JsonForm(request.form)

    return render_template('index.html', form=form)

@app.route('/api', methods=['POST'])
def api():
    keyword = request.form['keyword']



    # # if there is data that searched before.
    if os.path.isfile('./bundles/{0}-bundle.json'.format(keyword)):
        with open('./bundles/{0}-bundle.json'.format(keyword)) as f:

            # data = json.loads(f.readlines())
            # print(f.read())
            # print(data)
            return jsonify(f.read())

    else:
        make_group(keyword)

        with open('./bundles/{0}-bundle.json'.format(keyword)) as f:
            data = json.loads(f.read())

            print(data)
            return jsonify(data)


@app.route('/fonts/<file>', methods=['GET'])
def fonts(file):
    return url_for('static', filename=file)



def make_tree(path):
    tree = dict(name=os.path.basename(path), children=[])
    try: lst = os.listdir(path)
    except OSError:
        pass #ignore errors
    else:
        for name in lst:
            fn = os.path.join(path, name)
            if os.path.isdir(fn):
                tree['children'].append(make_tree(fn))
            else:
                # print(fn)
                # with open(fn, 'r') as f:
                #     json.loads(f.read())['objects']['type']
                # print(name)
                tree['children'].append(dict(name=name))
    return tree

@app.route('/group/<name>', methods=['GET'])
def grouping(name):

    files = make_tree('grouping')

    # files = os.listdir('grouping')

    # for f in os.listdir(grouping):
    #     print(f)

    # onlyfiles = [f for f in os.listdir(mypath) if os.path.isfile(os.path.join(mypath, f))]

    # print(files)
    return render_template('group.html', target=name, tree=files)

@app.route('/killchain', methods=['GET', 'POST'])
def killchain():
    return 'killchain'

if __name__=='__main__':
    app.config.from_object(__name__)
    app.config['SECRET_KEY'] = 'tnarudhkTejsskdml~'
    app.run('0.0.0.0',port=1994, debug=True)


