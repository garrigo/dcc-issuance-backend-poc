from datetime import datetime
from flask import Blueprint, abort, request, jsonify, render_template
from sqlalchemy import text
from sqlalchemy.sql.base import Executable
from sqlalchemy.sql.expression import or_
from app.models import Flight, db

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
    transaction = db.engine.execute(text("SELECT * FROM Flights WHERE transaction_id=:id"), id=id).fetchone()
    return render_template('index.html',
                            query_type="transaction",
                            message="Transaction n° " +str(id)+":",
                            transaction=transaction)

# Given flight date and flight number, return the delay of departure and landing of a flight
@bp.route('/delays/flight', methods=['GET'])
def flight_delay():
    #Input sanitization
    try:
        date = datetime.strptime(request.args.get('date'), '%Y-%m-%d').date()
        number = request.args.get('number')
        if not (date and number):
            raise Exception()
    except:
        return render_template('index.html',
                                query_type="flight_delays",
                                message="Error: wrong argument(s).",
                                flights=[])
    #Query
    flights = db.engine.execute(text("SELECT dep_delay, arr_delay FROM Flights WHERE fl_date=:date AND op_carrier_fl_num=:number"), date=date, number=number).fetchall()
    return render_template('index.html',
                            query_type="flight_delays",
                            message="Flight(s) n° "+str(number)+" on date " +str(date)+":",
                            flights=[{'dep_delay': f.dep_delay, 'arr_delay': f.arr_delay} for f in flights])


# Given a date interval and a minimum delay D, return the description of the flights (number, date, source city, destination city) with a delay of at least D minutes within the time interval specified.
@bp.route('/delays/all', methods=['GET'])
def all_delays():
    #Input sanitization
    try:
        date_from = datetime.strptime(request.args.get('date_from'), '%Y-%m-%d').date()
        date_to = datetime.strptime(request.args.get('date_to'), '%Y-%m-%d').date()
        minimum_delay = request.args.get('minimum_delay', type=int)
        if not (str(date_from) and str(date_to) and str(minimum_delay)):
            raise Exception()
    except:
        return render_template('index.html',
                                query_type="all_delays",
                                message="Error: wrong argument(s).",
                                flights=[])
    #Query
    flights = db.engine.execute(text("SELECT op_carrier_fl_num, fl_date, origin_city_name, dest_city_name FROM Flights WHERE (fl_date BETWEEN :date_from AND :date_to) AND (arr_delay>=:delay OR dep_delay>=:delay)"), date_from=date_from, date_to=date_to, delay=minimum_delay).fetchall() 
    return render_template('index.html', query_type="all_delays",
                            message="Flights between " + str(date_from) + " and " + str(date_to) + " with a delay greater than "+str(minimum_delay)+" minutes:",
                            flights=[{'Flight number': f.op_carrier_fl_num, 'Flight date': f.fl_date, 'Origin city': f.origin_city_name, 'Destination city': f.dest_city_name} for f in flights])

# Given a time interval and a positive integer n, return the n airports which had the highest percentage of delayed departures (delayed departures/total departures).  
@bp.route('/delays/airports', methods=['GET'])
def delays_statistics():
    #Input sanitization
    try:
        time_from = datetime.strptime(request.args.get('time_from'), '%H:%M').strftime('%H%M')
        time_to = datetime.strptime(request.args.get('time_to'), '%H:%M').strftime('%H%M')
        top = request.args.get('top', type=int)
        if not (str(time_from) and str(time_to) and str(top)):
            raise Exception()
    except:
        return render_template('index.html',
                                query_type="airport_delays",
                                airports=[],
                                message="Error: wrong argument(s).")
    #Query
    rows = db.engine.execute(
        text("SELECT origin_airport_id, origin, AVG(CASE WHEN dep_delay>0 THEN 1.0 ELSE 0.0 END)*100 AS percentage FROM Flights WHERE dep_time BETWEEN :time_from AND :time_to GROUP BY origin_airport_id, origin ORDER BY percentage DESC LIMIT :top"),
            time_from=time_from,
            time_to=time_to,
            top=top).fetchall()
    return render_template('index.html', query_type="airport_delays",
                                message="Top " + str(top) + " ariports with the highest percentage of delayed departures between " +str(time_from)+ " and " + str(time_to)+":",
                                airports=[{'Airport ID': row.origin_airport_id, 'Airport name': row.origin,
                                'Percentage of delayed departures': str(round(row.percentage, 2))+"%"} for row in rows])
