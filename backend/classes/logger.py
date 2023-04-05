import logging
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from starlette.responses import Response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_logger = logging.getLogger("request_audit")
        request_logger.info(
            f"{request.method} {request.url.path} {request.client.host}"
        )

        return await call_next(request)


audit_log_handler = logging.FileHandler("logs/request_audit.log")
audit_log_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
audit_log_handler.setLevel(logging.INFO)

request_audit_logger = logging.getLogger("request_audit")
request_audit_logger.addHandler(audit_log_handler)
request_audit_logger.setLevel(logging.INFO)

