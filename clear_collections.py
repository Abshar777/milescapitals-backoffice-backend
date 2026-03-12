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

COLLECTIONS_TO_CLEAR = ["transaction_requests", "transactions", "treasury_transactions"]


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
#     # main()
    # clear_all_collections()


# write a function to clear all collections in the database

# def clear_all_collections():
#     client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
#     db = client[DB_NAME]

#     print(f"\nConnected to database: {DB_NAME}")
#     print("\nCollections to be cleared:")
#     for col in db.list_collection_names():
#         count = db[col].count_documents({})
#         print(f"  - {col}: {count} documents")

#     print(
#         "\n⚠️  WARNING: This will permanently delete all documents in the above collections!"
#     )
#     confirm = input("\nType 'YES' to confirm and proceed: ").strip()

#     if confirm != "YES":
#         print("Aborted. No collections were cleared.")
#         return

#     print("\nClearing collections...")
#     for col in db.list_collection_names():
#         result = db[col].delete_many({})
#         print(f"  ✓ {col}: deleted {result.deleted_count} documents")

#     print("\nDone! All specified collections have been cleared.")
#     client.close()


# def delete_by_crm_reference_id(crm_reference_id, collection_name="transaction_requests"):
#     """
#     Delete transaction(s) from a collection by crm_reference_id.

#     Args:
#         crm_reference_id: The CRM reference ID to search for (e.g. 5809117)
#         collection_name: The collection to delete from (default: transaction_requests)
#     """
#     client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
#     db = client[DB_NAME]
#     collection = db[collection_name]

#     # Try both int and string versions to be safe
#     query = {
#         "$or": [
#             {"crm_reference_id": crm_reference_id},
#             {"crm_reference_id": str(crm_reference_id)}
#         ]
#     }

#     # First, preview matching documents
#     matches = list(collection.find(query))

#     if not matches:
#         print(f"\n❌ No documents found with crm_reference_id = {crm_reference_id}")
#         client.close()
#         return

#     print(f"\nFound {len(matches)} document(s) with crm_reference_id = {crm_reference_id}:")
#     for doc in matches:
#         print(f"  - _id: {doc['_id']} | crm_reference_id: {doc.get('crm_reference_id')}")

#     print("\n⚠️  WARNING: This will permanently delete the above document(s)!")
#     confirm = input("\nType 'YES' to confirm and proceed: ").strip()

#     if confirm != "YES":
#         print("Aborted. No documents were deleted.")
#         client.close()
#         return

#     result = collection.delete_many(query)
#     print(f"\n✓ Deleted {result.deleted_count} document(s) with crm_reference_id = {crm_reference_id}")

#     client.close()



client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
db = client[DB_NAME]
# collection = db["transactions"]
result= db.treasury_accounts.update_one(
        {"account_id": "treasury_dff9b532e16e"}, {"$set": {"balance": 344667.32}}
    )
print(result)

# ── Entry point ─────────────────────────────────────────────────────────────
# delete_by_crm_reference_id(5809117)
