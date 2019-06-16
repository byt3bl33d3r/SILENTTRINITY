FROM python:3.7-stretch

RUN pip install -U pip
RUN pip install pipenv

RUN mkdir /Server
ADD Server/Pipfile* /Server/
WORKDIR /Server
RUN pipenv install

ADD Server /Server

CMD pipenv run python st.py
