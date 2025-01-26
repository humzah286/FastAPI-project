from typing import Optional, List
from fastapi import FastAPI, HTTPException, Body
from fastapi.params import Depends
from pymongo import MongoClient
from pydantic import BaseModel
from contextlib import asynccontextmanager
import hashlib
import time
import os
import redis.asyncio as redis
import auth


DATABASE_URL = os.getenv("MONGO_URI")
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = os.getenv("REDIS_PORT")


async def startup_redis():
    global redis_client
    redis_host = REDIS_HOST  # Use the service name defined in docker-compose
    redis_port = REDIS_PORT
    redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
    try:
        await redis_client.ping()  # Test connection
        print("Connected to Redis!")
    except redis.exceptions.ConnectionError:
        print("Could not connect to Redis!")


class Item(BaseModel):
    id: str
    name: str
    description: Optional[str]

class ItemCreate(BaseModel):
    name: str
    description: Optional[str]

class ItemUpdate(BaseModel):
    name: Optional[str]
    description: Optional[str]

class CacheItem(BaseModel):
    key: str
    value: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup:
    await startup_redis()
    app.mongodb_client = MongoClient(DATABASE_URL)
    app.mongodb = app.mongodb_client["mydatabase"]
    yield
    # Shutdown: 
    await redis_client.close()
    app.mongodb_client.close()


app = FastAPI(lifespan=lifespan)
app.include_router(auth.router)



@app.get("/")
def read_root():
    return {"message": "Hello, MongoDB is connected"}


@app.post("/items/")
def create_item(item: ItemCreate):
    collection = app.mongodb["items"]
    print(item)
    item = item.dict()
    result = collection.insert_one(item)
    print("done: ", result)
    return {"id": str(result.inserted_id), "name": item["name"], "description": item['description']}


@app.get("/items/")
def list_items():
    collection = app.mongodb["items"]
    items = []
    for item in collection.find({}):  # Include all fields, including _id
        item["id"] = str(item.pop("_id"))  # Rename _id to id and convert to string
        items.append(item)
    return {"items": items}


@app.post("/cache/")
async def set_cache(key: str = Body(...), value: str = Body(...)):
    print(f"key : {key}, value : {value}")
    await redis_client.set(key, value, ex=3600)  # Store value with a 1-hour expiration
    return {"message": f"Key '{key}' set with value '{value}'"}

@app.get("/cache/{key}")
async def get_cache(key: str):
    value = await redis_client.get(key)
    if value is None:
        return {"message": "Key not found"}
    return {"key": key, "value": value}


