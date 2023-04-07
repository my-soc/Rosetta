from fastapi import FastAPI
from strawberry.asgi import GraphQL
import os

from app.schema import schema
from classes.logger import RequestLoggingMiddleware
from classes.config import Config

if not os.path.exists(Config.MODELS_DIR):
    os.makedirs(Config.MODELS_DIR)

if not os.path.exists(Config.LOGGING_DIR):
    os.makedirs(Config.LOGGING_DIR)


app = FastAPI()
app.add_route("/", GraphQL(schema=schema))
app.add_middleware(RequestLoggingMiddleware)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, log_level="info")
