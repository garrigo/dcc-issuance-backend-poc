from datetime import date
import time
from flask import Blueprint, abort, request, jsonify, render_template, url_for, redirect
from app.func import *


bp = Blueprint('api', __name__)

YEAR_IN_SECONDS = 31557600

# Given a transaction ID, return all the stats of a unique flight
@bp.route('/sign', methods=['POST'])
def sign():
    #Input sanitization
    # try:
    #     id = request.args.get('id', type=int)
    #     if (not id):
    #         raise Exception()
    # except:
    #     return render_template('index.html',
    #                             query_type="transaction",
    #                             message="Error: wrong argument(s).",
    #                             transaction=[])

    if request.method == 'POST':
        today = int(time.mktime(time.strptime(str(date.today()), "%Y-%m-%d")))
        payload = {
            4: today+YEAR_IN_SECONDS,
            6: today,
            1: request.form['issued'],
            -260: {
                1: {
                    "v": [
                        {
                            "dn": int(request.form['dn']),
                            "ma": request.form['ma'],
                            "dt": request.form['dt'],
                            "mp": request.form['mp'],
                            "sd": int(request.form['sd']),
                            "tg": request.form['tg'],
                        }
                    ],
                    "nam": {
                        "fnt": request.form['fn'],
                        "fn": request.form['fn'],
                        "gnt": request.form['gn'],
                        "gn": request.form['gn'],
                    },
                    "ver": request.form['ver'],
                    "dob": request.form['dob'],
                }
            }
        }
        base45_data = sign_GP(payload, 0)
        return render_template('index.html',
                                page="generated_gp",
                                payload=base45_data
        )
    else:
        render_template('index.html', page="home")