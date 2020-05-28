FROM alpine

RUN apk -U add --upgrade docker bash coreutils gcc grep python3 py3-pip py3-cryptography

RUN pip3 install certbot certbot-dns-route53 watchdog python-dotenv \
        datetime termcolor pyaml

COPY . /app

RUN chmod +x /app/start.py

ENTRYPOINT [ "/app/start.py" ]