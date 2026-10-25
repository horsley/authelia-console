FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ARG PIP_INDEX_URL=https://mirrors.cloud.tencent.com/pypi/simple/
ENV PIP_INDEX_URL=${PIP_INDEX_URL}
WORKDIR /opt/console
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
EXPOSE 8096
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8096", "--no-access-log", "--no-proxy-headers"]
