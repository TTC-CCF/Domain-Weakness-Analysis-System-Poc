FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

COPY . /app
RUN apt update && apt install -y dnsutils 
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD [ "python3", "app.py" ]