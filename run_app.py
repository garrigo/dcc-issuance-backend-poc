from app import app
if __name__ == "__main__":
    #add exception to firewall when lan testing
    app.run("0.0.0.0", port=5000, ssl_context=('app/certs/SSL/ssl.pem', 'app/certs/SSL/ssl-key.pem'))
    # app.run("0.0.0.0", port=5000, ssl_context=('adhoc'))
