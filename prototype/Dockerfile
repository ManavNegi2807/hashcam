FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --system --uid 10001 abb \
    && mkdir -p /data && chown abb /data
COPY . .
USER abb
EXPOSE 8000
CMD ["uvicorn", "ui.api:build", "--factory", "--host", "0.0.0.0", "--port", "8000"]
