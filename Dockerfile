FROM python:3

COPY . /app
WORKDIR /app

RUN pip install -r requirements.txt

RUN pyinstaller app.py

ENTRYPOINT [ "/app/dist/app/app", "-d" ]
CMD [ "google.com" ]