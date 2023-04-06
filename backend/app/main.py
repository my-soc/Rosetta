from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from strawberry.asgi import GraphQL

from app.schema import schema
from classes.logger import RequestLoggingMiddleware


app = FastAPI()
app.add_route("/", GraphQL(schema=schema))
app.add_middleware(RequestLoggingMiddleware)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, log_level="info")
