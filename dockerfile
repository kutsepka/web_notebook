
FROM python:3.12.0a3-slim-bullseye

WORKDIR /app

COPY requirements.txt requirements.txt
RUN python3 -m pip install -r requirements.txt

COPY . .
CMD [ "python3", "hello.py" ]
