# Green Pass QR Issuance Backend

---

## How to test (POSTGRES)

### Using docker
- Build the image with `docker build -t qr -f Dockerfile_pg .`
- Spin app the application container: `docker run -p 5000:5000 --rm --name "qr" -d qr`
- When needed, stop the containers with `docker stop qr`
- Open 'localhost:5000' on a browser