from datetime import date
import time
from flask import Blueprint, abort, request, jsonify, render_template, url_for, redirect
from app.func import *


bp = Blueprint('api', __name__)

    
YEAR_IN_SECONDS = 31557600

# Given a transaction ID, return all the stats of a unique flight
@bp.route('/sign', methods=['POST'])
def sign():

    if request.method == 'POST':
        today = int(time.mktime(time.strptime(str(date.today()), "%Y-%m-%d")))
        cert_type = request.form['type']
        if (cert_type == 'v'):
            payload = {
                4: today+YEAR_IN_SECONDS,
                6: today,
                1: request.form['issued'],
                -260: {
                    1: {
                        "v": [
                            {
                                "tg": request.form['tg'],
                                "mp": request.form['mp'],
                                "ma": request.form['ma'],
                                "dn": int(request.form['dn']),
                                "sd": int(request.form['sd']),
                                "dt": request.form['dt'],
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
        elif (cert_type == 't'):
            payload = {
                4: today+YEAR_IN_SECONDS,
                6: today,
                1: request.form['issued'],
                -260: {
                    1: {
                        "t": [
                            {
                                "tg": request.form['tg'],
                                "tt": request.form['tt'],
                                "ma": request.form['ma'],
                                "sc": request.form['sc'],
                                "tr": request.form['tr'], 
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
        elif(cert_type == 'r'):
            payload = {
                4: today+YEAR_IN_SECONDS,
                6: today,
                1: request.form['issued'],
                -260: {
                    1: {
                        "r": [
                            {
                                "tg": request.form['tg'],
                                "fr": request.form['fr'],
                                "df": request.form['df'],
                                "du": request.form['du'],
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
        else:
            render_template('index.html', generated=False)

        base45_data = sign_GP(payload, 0)

        return render_template('index.html',
                                generated=True,
                                payload=base45_data
        )
    else:
        render_template('index.html', generated=False)