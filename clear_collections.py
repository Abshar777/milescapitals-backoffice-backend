"""
Script to clear specific MongoDB collections.
Reads MONGO_URL and DB_NAME from the .env file in the same directory.
"""

import os
from pathlib import Path
from dotenv import load_dotenv
from pymongo import MongoClient

# Load .env from same directory as this script
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]

COLLECTIONS_TO_CLEAR = [
    "transactions",

]


def main():
    client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
    db = client[DB_NAME]

    print(f"\nConnected to database: {DB_NAME}")
    print("\nCollections to be cleared:")
    for col in COLLECTIONS_TO_CLEAR:
        count = db[col].count_documents({})
        print(f"  - {col}: {count} documents")

    print(
        "\n⚠️  WARNING: This will permanently delete all documents in the above collections!"
    )
    confirm = input("\nType 'YES' to confirm and proceed: ").strip()

    if confirm != "YES":
        print("Aborted. No collections were cleared.")
        return

    print("\nClearing collections...")
    for col in COLLECTIONS_TO_CLEAR:
        result = db[col].delete_many({})
        print(f"  ✓ {col}: deleted {result.deleted_count} documents")

    print("\nDone! All specified collections have been cleared.")
    client.close()


# if __name__ == "__main__":
#     main()
#     # clear_all_collections()





# write a function to clear all collections in the database

def clear_all_collections():
    client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
    db = client[DB_NAME]

    print(f"\nConnected to database: {DB_NAME}")
    print("\nCollections to be cleared:")
    for col in db.list_collection_names():
        count = db[col].count_documents({})
        print(f"  - {col}: {count} documents")

    print(
        "\n⚠️  WARNING: This will permanently delete all documents in the above collections!"
    )
    confirm = input("\nType 'YES' to confirm and proceed: ").strip()

    if confirm != "YES":
        print("Aborted. No collections were cleared.")
        return

    print("\nClearing collections...")
    for col in db.list_collection_names():
        result = db[col].delete_many({})
        print(f"  ✓ {col}: deleted {result.deleted_count} documents")

    print("\nDone! All specified collections have been cleared.")
    client.close()


clear_all_collections()