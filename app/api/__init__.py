from datetime import datetime
from flask import Blueprint, abort, request, jsonify, render_template
from app.func import *

bp = Blueprint('api', __name__)

# Given a transaction ID, return all the stats of a unique flight
@bp.route('/sign', methods=['GET'])
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
    #Query
    
    # return render_template('index.html',
    #                         query_type="transaction",
    #                         message="Transaction n° " +str(id)+":",
    #                         transaction=[])
    base45_data = sign_GP("D2844DA20448349A42B0C2D0728E0126A05900A9A4041A645D8180061A6109246901624954390103A101A4617681A662646E02626D616D4F52472D3130303033303231356264746A323032312D30382D3032626D706C45552F312F32302F313532386273640262746769383430353339303036636E616DA463666E746641525249474F62666E6641525249474F63676E7467474941434F4D4F62676E67474941434F4D4F6376657265312E302E3063646F626A313939352D30352D313858404BCB8A4680476BBECFB3C9D7B7E14402164E016E6D4D7CD8A221DBDA9205044F3654F9C17C2D4F03BDF24BA55755D374B381976439D7960406399A46D404A466")
    qrBuildJPG(base45_data)
    return "Ding"