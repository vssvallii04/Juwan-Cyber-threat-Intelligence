"""
Main entry point for the Cyber Threat Intelligence application
"""
from src.cti import create_app

# Create FastAPI application
app = create_app()

if __name__ == "__main__":
    import uvicorn
    
    # Run the application
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        reload=True
    )
