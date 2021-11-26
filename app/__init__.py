from config import Config
from flask import Flask
from flask_sqlalchemy import SQLAlchemy as _BaseSQLAlchemy
from flask_migrate import Migrate

app = Flask(__name__)
app.config.from_object(Config)

class SQLAlchemy(_BaseSQLAlchemy):
    def apply_pool_defaults(self, app, options):
        options = super().apply_pool_defaults(app, options)
        options["pool_pre_ping"] = True
        return options

db = SQLAlchemy(app)
db.create_all()

app.config['SQLALCHEMY_POOL_RECYCLE'] = 28000
app.config['SQLALCHEMY_POOL_TIMEOUT'] = 20000
app.config['SQLALCHEMY_POOL_SIZE'] = 10
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 0

migrate = Migrate(app, db, compare_type=True)

from app.errors import bp as errors_bp
app.register_blueprint(errors_bp)

from app import routes, models