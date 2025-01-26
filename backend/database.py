from pymongo import MongoClient
import os

DATABASE_URL = os.getenv("MONGO_URI")

mongoClient = MongoClient(DATABASE_URL)

def get_db():
    return mongoClient

