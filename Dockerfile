# mail-send — one process, its own image. The compose service that runs it, the socket
# directory it listens in and the env file it reads belong to whoever runs it.
# Not hardened: it runs as root and its base image and packages are not pinned.
FROM python:3.12-slim
RUN python -m venv /opt/mail/venv
COPY requirements.txt /opt/mail/requirements.txt
RUN /opt/mail/venv/bin/pip install --no-cache-dir -r /opt/mail/requirements.txt
COPY . /opt/mail
WORKDIR /opt/mail
ENV MAIL_SEND_PYTHON=/opt/mail/venv/bin/python
ENTRYPOINT ["/opt/mail/run.sh"]
