"""Domain errors mapped to HTTP responses by the FastAPI handlers."""

from __future__ import annotations


class ServiceError(Exception):
    status_code = 400
    code = "service_error"

    def __init__(self, message: str, *, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class NotFoundError(ServiceError):
    status_code = 404
    code = "not_found"


class ConflictError(ServiceError):
    status_code = 409
    code = "conflict"


class ValidationError(ServiceError):
    status_code = 422
    code = "validation_error"
