FROM python

RUN mkdir /app
WORKDIR /app
ADD . /app

RUN pip install -r requirements.txt

USER nobody

CMD [ "python", "/app/main.py" ]
