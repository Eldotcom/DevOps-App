FROM python:3.10-slim

# משתני סביבה ל־Flask
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=development

# תלות מערכת
RUN apt-get update && apt-get install -y \
    curl \
    chromium-driver \
    chromium \
    && rm -rf /var/lib/apt/lists/*

# יצירת תיקייה לעבוד בה
WORKDIR /app

# העתקת קבצי הקוד לתוך /app
COPY . /app

# התקנת ספריות
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN pip install selenium webdriver-manager

# בדיקה מה יש בתיקייה
RUN ls -la

EXPOSE 5000

CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
