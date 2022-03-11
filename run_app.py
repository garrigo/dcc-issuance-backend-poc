from app import app
if __name__ == "__main__":
    app.run("0.0.0.0", port=5000, ssl_context=('app/certs/SSL/server.crt', 'app/certs/SSL/server.key'))
    # app.run("0.0.0.0", port=5000, ssl_context=('adhoc'))
