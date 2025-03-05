from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os
from app.database import Database

# Import and include importing api end points 
from app.routes import child as child_routes
from app.routes import parent as parent_routes
from app.routes import message as message_routes

# testing database connection before starting the app
db = Database()
if db.test_database_connection():
    print(f"Connected to database '{db.config['database']}'!")
else:
    print("Failed to connect to the database. Exiting...")
    exit(1)  # Exit the program if the database connection fails

# Initialize FastAPI
app = FastAPI()

# Enable CORS for Flutter connections
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(child_routes.router, prefix="/api", tags=["Child"])
app.include_router(parent_routes.router, prefix="/api", tags=["Parent"])
app.include_router(message_routes.router, prefix="/api", tags=["Message"])

@app.get("/")
def read_root():
    return {"message": "أنيس .. رفيق طفلك الذي تثق به"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
