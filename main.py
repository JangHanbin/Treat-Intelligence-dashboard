from flask import Flask,jsonify,abort,make_response,json, render_template, request, flash, redirect, url_for
from flask_bootstrap import Bootstrap
from attack_search import Attack
app = Flask(__name__)
Bootstrap(app)

@app.route('/')
def root():
    return render_template('index.html')

@app.route('/api', methods=['GET', 'POST'])
def api():
    keyword = request.form['keyword']
    attack = Attack()
    attack_json = attack.get_bundle_json(keyword)

    return attack_json

if __name__=='__main__':
    app.config.from_object(__name__)
    app.config['SECRET_KEY'] = 'tnarudhkTejsskdml~'
    app.run('0.0.0.0',port=1994, debug=True)


