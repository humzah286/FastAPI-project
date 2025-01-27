from pymongo import MongoClient
import os

DATABASE_URL = os.getenv("MONGO_URI")

mongoClient = MongoClient(DATABASE_URL)
mongoClient["mydatabase"]["users"].create_index("email", unique=True)

def get_db():
    return mongoClient

