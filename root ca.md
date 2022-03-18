openssl genrsa -aes256 -out ca-key.pem 4096
openssl req -new -x509 -sha256 -days 3650 -key ca-key.pem -out ca.pem
openssl genrsa -out ssl-key.pem 4096
openssl req -new -sha256 -subj "/CN=dcc_issuer" -key ssl-key.pem -out ssl.csr
echo "subjectAltName=IP:192.168.1.111" >> extfile.cnf
openssl x509 -req -sha256 -days 3650 -in ssl.csr -CA ca.pem -CAkey ca-key.pem -out cert.pem -extfile extfile.cnf -CAcreateserial
cat cert.pem > fullchain.pem
cat ca.pem > fullchain.pem
"import private ssl key and fullchain.pem in server"
"import root ca.pem in os or browser of every machine, example:"
"windows -> powershell admin -> Import-Certificate -FilePath 'E:\Github\Web Application\app\certs\CA\ca.pem' -CertStoreLocation Cert:\LocalMachine\Root"

