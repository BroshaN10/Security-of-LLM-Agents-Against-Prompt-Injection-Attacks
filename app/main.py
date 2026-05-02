from fastapi import FastAPI
from app.agent import process_query

app = FastAPI()

@app.post("/query")
async def query(data: dict):
    return process_query(
        user_input=data["input"],
        role=data.get("role", "user")
    )