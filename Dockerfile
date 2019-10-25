FROM python:3.7-alpine3.10
WORKDIR /SILENTTRINITY
RUN apk upgrade --update-cache --available
RUN apk add build-base
RUN apk add bzip2-dev zlib-dev sqlite-dev readline-dev libbz2 \
ncurses-dev wget libffi-dev xz-dev openssl-dev tk-dev llvm ipython
RUN pip install shiv
RUN pip install ipython
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . ./
EXPOSE 80 443 5000 8080
ENTRYPOINT ["python3.7", "st.py", "teamserver", "${HOST_IP}", "${PASSWORD}"]
