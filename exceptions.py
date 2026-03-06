"""
Custom exception handlers and error response schemas
"""
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from logger import get_logger

logger = get_logger(__name__)


class CTIException(Exception):
    """Base exception for Cyber Threat Intelligence API"""
    
    def __init__(
        self,
        message: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        error_code: str = "GENERIC_ERROR"
    ):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        super().__init__(self.message)


class ValidationError(CTIException):
    """Raised when input validation fails"""
    def __init__(self, message: str):
        super().__init__(
            message=message,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error_code="VALIDATION_ERROR"
        )


class MissingModelError(CTIException):
    """Raised when required model is not found"""
    def __init__(self, model_name: str):
        super().__init__(
            message=f"Required model '{model_name}' not found or failed to load",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            error_code="MODEL_NOT_AVAILABLE"
        )


class ProcessingError(CTIException):
    """Raised when threat analysis fails"""
    def __init__(self, message: str, module: str = "unknown"):
        super().__init__(
            message=f"Error processing {module}: {message}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code="PROCESSING_ERROR"
        )


def register_exception_handlers(app: FastAPI):
    """Register all custom exception handlers with FastAPI app"""
    
    @app.exception_handler(CTIException)
    async def cti_exception_handler(request: Request, exc: CTIException):
        logger.warning(
            f"CTI Exception: {exc.error_code} - {exc.message}",
            extra={"path": request.url.path}
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "status": "error",
                "error_code": exc.error_code,
                "message": exc.message,
                "path": request.url.path
            }
        )
    
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        logger.warning(
            f"Validation Error: {exc}",
            extra={"path": request.url.path}
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "status": "error",
                "error_code": "VALIDATION_ERROR",
                "message": "Request validation failed",
                "details": exc.errors()
            }
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        logger.error(
            f"Unhandled Exception: {type(exc).__name__} - {str(exc)}",
            extra={"path": request.url.path},
            exc_info=True
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "error_code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred. Please contact support.",
                "path": request.url.path
            }
        )


def create_error_response(
    message: str,
    error_code: str = "ERROR",
    module: str = None,
    status_code: int = status.HTTP_400_BAD_REQUEST
) -> dict:
    """Create standardized error response"""
    response = {
        "status": "error",
        "error_code": error_code,
        "message": message
    }
    if module:
        response["module"] = module
    return response


def create_success_response(data: dict, status_msg: str = "success") -> dict:
    """Create standardized success response"""
    return {
        "status": status_msg,
        "data": data
    }
