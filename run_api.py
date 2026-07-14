#!/usr/bin/env python3
"""
run_api.py
==========
Starts the CTEM FastAPI server.
"""
import uvicorn

from logging_utils import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)

if __name__ == "__main__":
    logger.info("Starting CTEM API server")
    logger.info("Swagger documentation: http://127.0.0.1:8000/docs")
    logger.info("ReDoc documentation: http://127.0.0.1:8000/redoc")
    logger.info("Press Ctrl+C to stop.")

    uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=True)
