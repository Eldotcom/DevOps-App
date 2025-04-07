# Dockerfile

FROM python:3.10-slim

# משתנה סביבתי ל־Flask
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=development

# התקנת תלות של מערכת
RUN apt-get update && apt-get install -y \
    curl \
    chromium-driver \
    chromium \
    && rm -rf /var/lib/apt/lists/*

# התקנת הספריות של Python
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN pip install selenium webdriver-manager

# העתקת קוד האפליקציה
COPY . /app
WORKDIR /app

EXPOSE 5000

CMD ["flask", "run"]
