FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATABASE_PATH=/data/proofs.db
# 证明记录、撤销记录与信任根版本均存放在 $DATABASE_PATH,
# 通过下方命名卷 (/data) 持久化; 未配置信任根版本时回退到
# TRUSTED_ROOT_ISSUERS 环境变量 (留空 = 开发模式)。

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /data && useradd -r -u 10001 appuser && chown -R appuser /data
USER appuser

VOLUME ["/data"]

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8080')+'/health').read()" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
