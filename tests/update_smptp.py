import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime, timezone

MONGO_URL = "mongodb+srv://abshar:C4oWeDhJcSMpmqeq@cluster0.k6iwxga.mongodb.net/?appName=Cluster0"
DB_NAME = "miles_ac_db"
print("ahhaha")


async def update_smtp():
    print(f"Connecting to {MONGO_URL}...")
    client = AsyncIOMotorClient(MONGO_URL)
    db = client[DB_NAME]

    now = datetime.now(timezone.utc).isoformat()

    updates = {
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "smtp_email": "no-replyac@milescapitals.com",
        "smtp_password": "geoksfeouosodovt",
        "smtp_from_email": "no-replyac@milescapitals.com",
        "director_emails": ["7209safvan@gmail.com"],
        "updated_at": now,
        "updated_by": "system",
    }

    existing = await db.app_settings.find_one({"setting_type": "email"})

    if existing:
        await db.app_settings.update_one({"setting_type": "email"}, {"$set": updates})
        print("Updated existing email settings.")
    else:
        updates["setting_type"] = "email"
        updates["created_at"] = now
        await db.app_settings.insert_one(updates)
        print("Created new email settings.")


if __name__ == "__main__":
    asyncio.run(update_smtp())
