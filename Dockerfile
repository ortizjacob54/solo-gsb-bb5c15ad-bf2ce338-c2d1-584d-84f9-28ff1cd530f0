FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATABASE_PATH=/data/proofs.db

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# 启动时 (app.main lifespan -> init_db) 自动建表/迁移:
# proofs、revocations 以及信任根版本表 (trust_root_*)，
# 在已挂载的旧数据卷上使用 CREATE TABLE IF NOT EXISTS 平滑升级。
RUN mkdir -p /data && useradd -r -u 10001 appuser && chown -R appuser /data
USER appuser

VOLUME ["/data"]

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8080')+'/health').read()" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
