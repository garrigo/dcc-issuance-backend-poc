# DCC Issuance Backend

Simulation of an issuance backend for Digital COVID Certificates with improved space complexity.

---

## How to test 
# Root CA & SSL
- Create CA and key-pair in app/certs/SSL/ as in `root ca.md`
- Generate a key-pair `openssl req -x509 -newkey rsa:4096 -keyout key_ta.pem -out cert_ta.pem -days 365 -nodes` in app/certs/TrustAnchor/
# CAs
- Install JAVA and use `keytool -importcert -alias dgcg_trust_anchor -file cert_ta.pem -keystore ta.jks -storepass dgcg-p4ssw0rd`
# DSC
- `openssl ecparam -genkey -name prime256v1 -out private_key.pem` to generate new private key ecdsa p256    
- `openssl genrsa -out private.pem 2048` for RSA
- `openssl req -new -key private_key.pem -x509 -nodes -days 365 -out cert.pem` to use the private key to generate certificate
- `keytool -import -alias x -file certx.pem -keystore publicKey.jks` to export certificate to public javakeystore (trust store)
- `openssl pkcs12 -export -in cert.pem -inkey private_key.pem -out bundle.p12` to export private+certificate to other bundle (key store)
- `keytool -importkeystore -deststorepass private -destkeystore private_key.jks -srckeystore bundle.p12 -srcstoretype PKCS12` to import to jks


## Using terminal
- Run `pip3 install -r requirements.txt`
- Run `python3 run_app.py`
- Open 'localhost:5000'

### Using docker
- Build the image with `docker build -t issuer -f Dockerfile_pg .`
- Spin app the application container: `docker run -p 5000:5000 --rm --name "issuer" -d issuer`
- When needed, stop the containers with `docker stop issuer`
- Open 'localhost:5000'

