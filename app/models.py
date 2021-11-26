from flask import url_for
from app import db

class Flight(db.Model):
    __tablename__ = 'flights'
    transaction_id = db.Column(db.Integer, primary_key=True)
    year = db.Column(db.Integer)
    day_of_week = db.Column(db.Integer)
    fl_date = db.Column(db.Date)
    op_carrier_airline_id = db.Column(db.Integer)
    op_carrier_fl_num = db.Column(db.String(10))
    origin_airport_id = db.Column(db.Integer)
    origin = db.Column(db.String(3))
    origin_city_name = db.Column(db.String(100))
    origin_state_nm = db.Column(db.String(100))
    dest_airport_id = db.Column(db.Integer)
    dest = db.Column(db.Integer)
    dest_city_name = db.Column(db.String(100))
    dest_state_nm = db.Column(db.String(100))
    dep_time = db.Column(db.Integer)
    dep_delay = db.Column(db.Float)
    arr_time = db.Column(db.Integer)
    arr_delay = db.Column(db.Float)
    cancelled = db.Column(db.Boolean)
    air_time = db.Column(db.Integer)

    def __repr__(self):
        return f'<Flight {self.transaction_id}>'

    def serialize(self):
        return {**{c.name: getattr(self, c.name) for c in self.__table__.columns}, **{
            '_links': {
                "self": url_for("flights.get_flight", id=self.transaction_id),
                # "collection": url_for("flights.get_all_flights")
            }
        }}