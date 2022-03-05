from datetime import date
import time
from flask import Blueprint, abort, request, jsonify, render_template, url_for, redirect
from app.func import *


bp = Blueprint('api', __name__)

HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']
YEAR_IN_SECONDS = 31557600

# Given a transaction ID, return all the stats of a unique flight
@bp.route('/sign', methods=HTTP_METHODS)
def sign():

    if request.method == 'POST':
        today = int(time.mktime(time.strptime(str(date.today()), "%Y-%m-%d")))
        dob = int(time.mktime(time.strptime(request.form['dob'], "%Y-%m-%d")))
        cert_type = request.form['type']
        

        if (cert_type == 'v'):
            vax_date = int(time.mktime(time.strptime(request.form['dt'], "%Y-%m-%d")))
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
                                # "dt": request.form['dt'],
                                "dt": vax_date
                            }
                        ],
                        "nam": {
                            "fnt": request.form['fn'],
                            "fn": request.form['fn'],
                            "gnt": request.form['gn'],
                            "gn": request.form['gn'],
                        },
                        "ver": request.form['ver'],
                        "dob": dob,
                        # "dob": request.form['dob'],
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
                                "sc": request.form['sc']+":00"+request.form['time_zone'],
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
                        "dob": dob,
                        # "dob": request.form['dob'],
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
                        "dob": dob,
                        # "dob": request.form['dob'],
                    }
                }
            }
        else:
            render_template('index.html', generated=False)

        base45_data = sign_newcose(payload, 0)

        return render_template('index.html',
                                generated=True,
                                payload=base45_data
        )
    else:
        return render_template('index.html', generated=False)