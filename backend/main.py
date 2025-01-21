from typing import Optional, List
from fastapi import FastAPI, HTTPException
from fastapi.params import Depends
from pymongo import MongoClient
from pydantic import BaseModel
from contextlib import asynccontextmanager
import hashlib
import time
import os


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


DATABASE_URL = os.getenv("MONGO_URI")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup:
    app.mongodb_client = MongoClient(DATABASE_URL)
    app.mongodb = app.mongodb_client["mydatabase"]
    yield
    # Shutdown: 
    app.mongodb_client.close()


app = FastAPI(lifespan=lifespan)


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


