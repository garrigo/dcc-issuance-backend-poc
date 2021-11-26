from datetime import datetime
from flask import Blueprint, abort, request, jsonify, render_template

bp = Blueprint('flights', __name__)

# Given a transaction ID, return all the stats of a unique flight
@bp.route('/transaction', methods=['GET'])
def get_flight():
    #Input sanitization
    try:
        id = request.args.get('id', type=int)
        if (not id):
            raise Exception()
    except:
        return render_template('index.html',
                                query_type="transaction",
                                message="Error: wrong argument(s).",
                                transaction=[])
    #Query

    return render_template('index.html',
                            query_type="transaction",
                            message="Transaction n° " +str(id)+":",
                            transaction=[])
