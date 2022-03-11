# DCC QR Issuance Backend

---

## How to test 
- Create key-pair in app/certs/SSL/ as in https://kracekumar.com/post/54437887454/ssl-for-flask-local-development/ but using at least 2048 bits for RSA
- Generate a key-pair `openssl req -x509 -newkey rsa:4096 -keyout key_ta.pem -out cert_ta.pem -days 365 -nodes` in app/certs/TrustAnchor/
- Install JAVA and use `keytool -importcert -alias dgcg_trust_anchor -file cert_ta.pem -keystore ta.jks -storepass dgcg-p4ssw0rd`
-` openssl ecparam -genkey -name prime256v1 -out private_key.pem` to generate new private key ecdsa p256    
- `openssl req -new -key private_key.pem -x509 -nodes -days 365 -out cert.pem` to use the private key to generate certificate
- `keytool -import -alias x -file certx.pem -keystore publicKey.jks` to export certificate to javakeystore
- `openssl pkcs12 -export -in cert.pem -inkey private.pem -out bundle_1.p12` to export private+certificate to other bundle
- `keytool -importkeystore -deststorepass private -destkeystore privateKey.jks -srckeystore bundle_1.p12 -srcstoretype PKCS12` to import to jks


## Using terminal
- Run `pip3 install -r requirements.txt`
- Run `python3 run_app.py`
- Open 'localhost:5000'

### Using docker
- Build the image with `docker build -t issuer -f Dockerfile_pg .`
- Spin app the application container: `docker run -p 5000:5000 --rm --name "issuer" -d issuer`
- When needed, stop the containers with `docker stop issuer`
- Open 'localhost:5000'

