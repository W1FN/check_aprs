FROM python:alpine

COPY . check_aprs

RUN pip install ./check_aprs

CMD check_aprs
