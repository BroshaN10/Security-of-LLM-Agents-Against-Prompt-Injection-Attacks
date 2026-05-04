from fastapi import FastAPI
from app.agent import process_query

app = FastAPI()

@app.post("/query")
async def query(data: dict):
    # support both legacy format {"input": "..."} and new chat format {"user": "user1", "message": "..."}
    if "message" in data:
        message = data.get("message")
        user = data.get("user", "anonymous")
        return process_query(user_input=message, user=user)

    return process_query(
        user_input=data.get("input")
    )