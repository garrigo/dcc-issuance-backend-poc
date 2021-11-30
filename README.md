# Green Pass QR Issuance Backend

---

## How to test 

- Run `pip3 install -r requirements.txt`
- Run `python3 run_app.py`
- Open 'localhost:5000'

### Using docker
- Build the image with `docker build -t issuer -f Dockerfile_pg .`
- Spin app the application container: `docker run -p 5000:5000 --rm --name "issuer" -d issuer`
- When needed, stop the containers with `docker stop issuer`
- Open 'localhost:5000'