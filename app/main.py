from fastapi import FastAPI
from app.agent import process_query

app = FastAPI()

@app.post("/query")
async def query(data: dict):
    user_input = data.get("message", data.get("input", ""))
    return process_query(
        user_input=user_input,
        user=data.get("user", "anonymous"),
        role=data.get("role", "user")
    )