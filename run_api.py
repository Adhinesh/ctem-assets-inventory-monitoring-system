#!/usr/bin/env python3
"""
run_api.py
==========
Starts the CTEM FastAPI server.
"""
import sys
import os
import uvicorn

if __name__ == "__main__":
    print("🚀 Starting CTEM API Server...")
    print("📖 Swagger Documentation: http://127.0.0.1:8000/docs")
    print("📖 ReDoc Documentation:   http://127.0.0.1:8000/redoc")
    print("Press Ctrl+C to stop.\n")
    
    # Run uvicorn programmatically
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=True)
