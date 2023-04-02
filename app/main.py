from fastapi import FastAPI
from strawberry.asgi import GraphQL
from .api.schema import schema
from .logger import RequestLoggingMiddleware


app = FastAPI()
app.add_middleware(RequestLoggingMiddleware)
app.add_route("/", GraphQL(schema=schema))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, log_level="info")
