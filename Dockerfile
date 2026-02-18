FROM python:3.12-slim
WORKDIR /app

# 先安裝相依（使用你 repo 的 backend/requirements.txt）
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# 複製程式與靜態檔
COPY backend/ /app/backend/
COPY web/ /app/web/
COPY alembic.ini /app/alembic.ini
COPY alembic/ /app/alembic/

# 由 release/run 注入版本（例如 git sha），供 pipeline log 追蹤程式版本
ARG APP_GIT_SHA=unknown
ENV APP_GIT_SHA=${APP_GIT_SHA}

# 入口（可由 .env 的 APP_MODULE 覆蓋），預設 backend.app:app
ENV APP_MODULE=backend.app:app
EXPOSE 8000
CMD ["sh","-lc","uvicorn ${APP_MODULE} --host 0.0.0.0 --port 8000"]
