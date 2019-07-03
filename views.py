from run import app
from flask import jsonify, render_template, url_for, Flask, request, redirect

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/authentication')
def authentication():
    return render_template('auth.html')