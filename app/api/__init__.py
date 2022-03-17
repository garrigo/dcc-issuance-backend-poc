from datetime import date, datetime
import time
from flask import Blueprint, request, render_template, make_response
from app.func import *


bp = Blueprint('api', __name__)
csp = ""


HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']
YEAR_IN_SECONDS = 31557600

# Given a transaction ID, return all the stats of a unique flight
@bp.route('/sign', methods=HTTP_METHODS)
def sign():

    if request.method == 'POST':
        dob = int(time.mktime(time.strptime(request.form['dob'], "%Y-%m-%d"))) 
        offset = int((datetime.fromtimestamp(dob) -datetime.utcfromtimestamp(dob)).total_seconds())
        dob += offset
        today = int(time.mktime(time.strptime(str(date.today()), "%Y-%m-%d")))
        offset = int((datetime.fromtimestamp(today) -datetime.utcfromtimestamp(today)).total_seconds())
        today += offset
        cert_type = request.form['type']
        if (cert_type == 'v'):
            vax_date = int(time.mktime(time.strptime(request.form['dt'], "%Y-%m-%d"))) + offset
            payload = {
                4: today+YEAR_IN_SECONDS,
                6: today,
                # 1: request.form['issued'],
                -260: {
                    1: {
                        "v": [
                            {
                                "tg": int(request.form['tg']),
                                "mp": int(request.form['mp']),
                                # "ma": request.form['ma'],
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
                        # "ver": request.form['ver'],
                        "dob": dob,
                        # "dob": request.form['dob'],
                    }
                }
            }
        elif (cert_type == 't'):
            test_date = int(time.mktime(time.strptime(request.form['sc'], "%Y-%m-%dT%H:%M"))) + offset
            payload = {
                4: today+YEAR_IN_SECONDS,
                6: today,
                # 1: request.form['issued'],
                -260: {
                    1: {
                        "t": [
                            {
                                "tg": int(request.form['tg']),
                                # "tt": request.form['tt'],
                                "ma": int(request.form['ma']),
                                # "sc": request.form['sc']+":00"+request.form['time_zone'],
                                "sc": test_date,
                                "tr": int(request.form['tr']), 
                            }
                        ],
                        "nam": {
                            "fnt": request.form['fn'],
                            "fn": request.form['fn'],
                            "gnt": request.form['gn'],
                            "gn": request.form['gn'],
                        },
                        # "ver": request.form['ver'],
                        "dob": dob,
                        # "dob": request.form['dob'],
                    }
                }
            }
        elif(cert_type == 'r'):
            fr_date = int(time.mktime(time.strptime(request.form['fr'], "%Y-%m-%d"))) + offset
            df_date = int(time.mktime(time.strptime(request.form['df'], "%Y-%m-%d"))) + offset
            du_date = int(time.mktime(time.strptime(request.form['du'], "%Y-%m-%d"))) + offset
            payload = {
                4: today+YEAR_IN_SECONDS,
                6: today,
                # 1: request.form['issued'],
                -260: {
                    1: {
                        "r": [
                            {
                                "tg": int(request.form['tg']),
                                # "fr": request.form['fr'],
                                # "df": request.form['df'],
                                # "du": request.form['du'],
                                "fr": fr_date,
                                "df": df_date,
                                "du": du_date,                                
                            }
                        ],
                        "nam": {
                            "fnt": request.form['fn'],
                            "fn": request.form['fn'],
                            "gnt": request.form['gn'],
                            "gn": request.form['gn'],
                        },
                        # "ver": request.form['ver'],
                        "dob": dob,
                        # "dob": request.form['dob'],
                    }
                }
            }
        else:
            response = make_response(render_template('index.html', generated=1, payload=[]))
            response.headers['Content-Security-Policy-Report-Only'] = csp
            return response
            

        base45_data = sign_newcose(payload)
        if not base45_data:
            base45_data =""
        response = make_response(render_template('index.html',
                                generated=1,
                                payload=base45_data
        ))
        response.headers['Content-Security-Policy-Report-Only'] = csp
        return response
    else:
        response = make_response(render_template('index.html', generated=""))
        response.headers['Content-Security-Policy-Report-Only'] = csp
        return response

@bp.route('/certificateList', methods=['GET'])
def certificateList():
    try:
        if request.method == 'GET':
            with open('./app/static/json/certificates.json', 'r') as f:
                data = json.load(f)
            return data
        else:
            return {}
    except Exception as e:
        return e

@bp.route('/vaccineList', methods=['GET'])
def vaccineList():
    try:
        if request.method == 'GET':
            with open('./app/static/json/vaccine-medicinal-product.json', 'r') as f:
                data = json.load(f)
            return data
        else:
            return {}
    except Exception as e:
        return e

@bp.route('/testList', methods=['GET'])
def testList():
    try:
        if request.method == 'GET':
            with open('./app/static/json/test-used.json', 'r') as f:
                data = json.load(f)
            return data
        else:
            return {}
    except Exception as e:
        return e

@bp.route('/diseaseList', methods=['GET'])
def diseaseList():
    try:
        if request.method == 'GET':
            with open('./app/static/json/disease-agent-targeted.json', 'r') as f:
                data = json.load(f)
            return data
        else:
            return {}
    except Exception as e:
        return e


@bp.route('/algorithmList', methods=['GET'])
def algorithmList():
    try:
        if request.method == 'GET':
            with open('./app/static/json/algorithm.json', 'r') as f:
                data = json.load(f)
            return data
        else:
            return {}
    except Exception as e:
        return e

@bp.route('/valueSets', methods=['GET'])
def valueSets():
    try:
        if request.method == 'GET':
            with open('./app/static/json/valueSets.json', 'r') as f:
                data = json.load(f)
            return data
        else:
            return {}
    except Exception as e:
        return e

@bp.route('/rules', methods=['GET'])
def rules():
    try:
        if request.method == 'GET':
            with open('./app/static/json/rules.json', 'r') as f:
                data = json.load(f)
            return data
        else:
            return {}
    except Exception as e:
        return e