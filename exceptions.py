"""
exceptions.py — Juwan CTI v3.0 Custom Exception Handlers
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from logger import get_logger

logger = get_logger(__name__)


class ValidationError(Exception):
    def __init__(self, message: str, field: str = None):
        self.message = message
        self.field = field
        super().__init__(message)


class ProcessingError(Exception):
    def __init__(self, message: str, module: str = None):
        self.message = message
        self.module = module
        super().__init__(message)


class ModelNotLoadedError(Exception):
    def __init__(self, model_name: str):
        self.message = f"Model '{model_name}' is not loaded. Run the training script first."
        super().__init__(self.message)


def register_exception_handlers(app: FastAPI):

    @app.exception_handler(ValidationError)
    async def validation_error_handler(request: Request, exc: ValidationError):
        logger.warning(f"CTI ValidationError: {exc.message}")
        return JSONResponse(
            status_code=422,
            content={
                "status": "error",
                "error_code": "VALIDATION_ERROR",
                "message": exc.message,
                "field": exc.field,
            },
        )

    @app.exception_handler(ProcessingError)
    async def processing_error_handler(request: Request, exc: ProcessingError):
        logger.error(f"CTI ProcessingError [{exc.module}]: {exc.message}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "error_code": "PROCESSING_ERROR",
                "message": exc.message,
                "module": exc.module,
            },
        )

    @app.exception_handler(ModelNotLoadedError)
    async def model_not_loaded_handler(request: Request, exc: ModelNotLoadedError):
        logger.error(f"CTI ModelNotLoadedError: {exc.message}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "error",
                "error_code": "MODEL_NOT_LOADED",
                "message": exc.message,
            },
        )

    @app.exception_handler(Exception)
    async def generic_error_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "error_code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred.",
            },
        )
