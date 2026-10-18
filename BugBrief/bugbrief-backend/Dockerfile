FROM python:3.12-slim
WORKDIR /app
RUN useradd -m app && mkdir /data && chown app /data
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY bugbrief bugbrief
USER app
ENV DB_PATH=/data/bugbrief.db
EXPOSE 8000
CMD ["uvicorn", "bugbrief.api:app", "--host", "0.0.0.0", "--port", "8000"]
