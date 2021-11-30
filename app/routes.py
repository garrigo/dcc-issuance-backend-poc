from flask import render_template
from app import app

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html', page="home")

from app.api import bp as flights_blueprint
app.register_blueprint(flights_blueprint)