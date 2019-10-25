FROM python:3.7-alpine3.10
WORKDIR /SILENTTRINITY
COPY . ./
RUN apk upgrade --update-cache --available
RUN apk add build-base
RUN apk add bzip2-dev zlib-dev sqlite-dev readline-dev libbz2 \
ncurses-dev wget libffi-dev xz-dev openssl-dev tk-dev llvm ipython
RUN pip install shiv
RUN pip install ipython
RUN pip install -r requirements.txt
EXPOSE 80 443 5000 8080
ENTRYPOINT ["/bin/sh", "entrypoint.sh"]
