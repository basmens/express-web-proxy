# Certificates

For development purposes, the source code is served on http://localhost:xxxx

To make your browser trusts this server, you need to install RootCA.crt
into the root certificates store of your computer.

## Generate HTTPS certificate (when needed)

The HTTPS certificate is valid for one year. When expired, a new certificate can be created
using the following commands:

```sh
  cd ./certs

# cspell: disable-next-line
  openssl req -new -nodes -newkey rsa:2048 -keyout localhost.key -out localhost.csr -subj "/C=NL/ST=Zuid-Holland/L=Zoetermeer/O=Bas-en-Ben/CN=localhost"

# cspell: disable-next-line
  openssl x509 -req -sha256 -days 365 -in localhost.csr -CA RootCA.crt -CAkey RootCA.key -CAcreateserial -extfile domains.ext -out localhost.crt
```


When needed a pfx file can be created using the command below.

```sh
  cd ./certs

# cspell: disable-next-line
  openssl pkcs12 -inkey localhost.key -in localhost.crt -export -out localhost.pfx
```

## Generate RootCA (when needed)

The RootCA will be valid until 31-12-2034. After that you can use the following command to generate a new one.  
You should add the new RootCA.crt to your root certificate store.

```sh
  cd ./certs

# cspell: disable-next-line
  openssl req -x509 -nodes -new -sha256 -days 3650 -newkey rsa:2048 -keyout RootCA.key -out RootCA.crt -subj "/C=NL/CN=Bas-en-Ben-Root-CA"
```
