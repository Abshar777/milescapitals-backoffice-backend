"""
chat.py — Direct messages and group channels.

All endpoints are registered on `chat_router`, which server.py includes into
`api_router` near the end of its startup sequence.  By the time server.py
executes `from chat import chat_router`, the three names we need from it
(db, get_current_user, upload_to_r2) are already defined, so the circular
reference is safe.
"""

import asyncio
import jwt as _jwt
import uuid
import base64
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import RedirectResponse, Response

from server import db, get_current_user, upload_to_r2, JWT_SECRET, JWT_ALGORITHM

chat_router = APIRouter()


# ═══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class _ConnManager:
    def __init__(self):
        self._conns: dict = {}

    async def connect(self, ws: WebSocket, uid: str):
        await ws.accept()
        self._conns.setdefault(uid, []).append(ws)

    def disconnect(self, ws: WebSocket, uid: str):
        lst = self._conns.get(uid, [])
        if ws in lst:
            lst.remove(ws)
        if not lst:
            self._conns.pop(uid, None)

    async def send_to(self, uid: str, payload: dict):
        for ws in list(self._conns.get(uid, [])):
            try:
                await ws.send_json(payload)
            except Exception:
                self.disconnect(ws, uid)

    async def broadcast(self, uids: list, payload: dict):
        for uid in set(uids):
            await self.send_to(uid, payload)


manager = _ConnManager()


@chat_router.websocket("/ws")
async def ws_endpoint(ws: WebSocket, token: str = Query(...)):
    uid = None
    # Try session token
    session = await db.user_sessions.find_one({"session_token": token}, {"_id": 0})
    if session:
        exp = session.get("expires_at")
        if isinstance(exp, str):
            exp = datetime.fromisoformat(exp)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp > datetime.now(timezone.utc):
            uid = session["user_id"]
    # Try JWT
    if not uid:
        try:
            payload = _jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            uid = payload.get("user_id")
        except Exception:
            pass
    if not uid:
        await ws.close(code=4001)
        return
    await manager.connect(ws, uid)
    try:
        while True:
            msg = await ws.receive_text()
            if msg == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(ws, uid)


# ═══════════════════════════════════════════════════════════════════════════════
# DIRECT MESSAGES
# ═══════════════════════════════════════════════════════════════════════════════

@chat_router.get("/messages/users")
async def get_users_for_messaging(user: dict = Depends(get_current_user)):
    """Get all users for message recipient selection (lightweight, no admin permission needed)"""
    users = await db.users.find(
        {"is_system": {"$ne": True}}, {"_id": 0, "user_id": 1, "name": 1, "email": 1, "role": 1}
    ).to_list(500)
    return [u for u in users if u.get("user_id") != user["user_id"]]


@chat_router.get("/messages/unread-count")
async def get_unread_messages_count(user: dict = Depends(get_current_user)):
    """Get total count of unread messages for the current user"""
    user_id = user["user_id"]
    unread_count = await db.user_messages.count_documents(
        {"recipient_id": user_id, "read": {"$ne": True}}
    )
    return {"count": unread_count}


@chat_router.get("/messages/conversations")
async def get_conversations(user: dict = Depends(get_current_user)):
    """Get all conversations for the current user"""
    user_id = user["user_id"]

    messages = (
        await db.user_messages.find(
            {"$or": [{"sender_id": user_id}, {"recipient_id": user_id}]}, {"_id": 0}
        )
        .sort("created_at", -1)
        .to_list(1000)
    )

    conversations = {}
    for msg in messages:
        partner_id = (
            msg["recipient_id"] if msg["sender_id"] == user_id else msg["sender_id"]
        )
        if partner_id not in conversations:
            partner = await db.users.find_one(
                {"user_id": partner_id},
                {"_id": 0, "user_id": 1, "name": 1, "email": 1, "role": 1},
            )
            if partner:
                conversations[partner_id] = {
                    "user_id": partner_id,
                    "name": partner.get("name", "Unknown"),
                    "email": partner.get("email", ""),
                    "role": partner.get("role", "user"),
                    "last_message": msg.get("content", "")[:50],
                    "last_message_at": msg.get("created_at"),
                    "unread_count": 0,
                }

        if msg["recipient_id"] == user_id and not msg.get("read"):
            if partner_id in conversations:
                conversations[partner_id]["unread_count"] += 1

    return list(conversations.values())


@chat_router.get("/messages/conversation/{recipient_id}")
async def get_conversation_messages(
    recipient_id: str, limit: int = 100, user: dict = Depends(get_current_user)
):
    """Get messages between current user and recipient"""
    user_id = user["user_id"]
    messages = (
        await db.user_messages.find(
            {
                "$or": [
                    {"sender_id": user_id, "recipient_id": recipient_id},
                    {"sender_id": recipient_id, "recipient_id": user_id},
                ]
            },
            {"_id": 0},
        )
        .sort("created_at", 1)
        .to_list(limit)
    )
    return messages


@chat_router.post("/messages/send")
async def send_user_message(
    request: Request,
    recipient_id: str = Form(...),
    content: str = Form(""),
    attachment: Optional[UploadFile] = File(None),
    user: dict = Depends(get_current_user),
):
    """Send a message to another user, optionally with a file attachment"""
    now = datetime.now(timezone.utc)

    if not recipient_id:
        raise HTTPException(status_code=400, detail="Recipient ID is required")

    recipient = await db.users.find_one({"user_id": recipient_id})
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    if not content.strip() and not attachment:
        raise HTTPException(status_code=400, detail="Message content or attachment is required")

    message_id = f"msg_{uuid.uuid4().hex[:12]}"

    attachment_data = None
    if attachment and attachment.filename:
        file_content = await attachment.read()
        if len(file_content) > 10 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="File size exceeds 10MB limit")
        attachment_url = upload_to_r2(
            file_content,
            attachment.filename,
            attachment.content_type or "application/octet-stream",
            "attachments",
        )
        attachment_data = {
            "filename": attachment.filename,
            "content_type": attachment.content_type or "application/octet-stream",
            "size": len(file_content),
            "url": attachment_url,
        }

    message_doc = {
        "message_id": message_id,
        "sender_id": user["user_id"],
        "sender_name": user["name"],
        "recipient_id": recipient_id,
        "recipient_name": recipient.get("name", "Unknown"),
        "content": content,
        "attachment": (
            {
                "filename": attachment_data["filename"],
                "content_type": attachment_data["content_type"],
                "size": attachment_data["size"],
            }
            if attachment_data
            else None
        ),
        "read": False,
        "created_at": now.isoformat(),
    }

    if attachment_data:
        await db.message_attachments.insert_one(
            {
                "message_id": message_id,
                "filename": attachment_data["filename"],
                "content_type": attachment_data["content_type"],
                "size": attachment_data["size"],
                "url": attachment_data["url"],
                "created_at": now.isoformat(),
            }
        )

    await db.user_messages.insert_one(message_doc)
    message_doc.pop("_id", None)
    if attachment_data:
        message_doc["attachment"] = {**message_doc.get("attachment", {}), "url": attachment_data.get("url", "")}
    asyncio.create_task(manager.broadcast([recipient_id, user["user_id"]], {
        "type": "dm_message", "message": message_doc,
    }))
    return message_doc


@chat_router.get("/messages/attachment/{message_id}")
async def get_message_attachment(
    message_id: str, user: dict = Depends(get_current_user)
):
    """Download a message attachment"""
    msg = await db.user_messages.find_one({"message_id": message_id}, {"_id": 0})
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")

    if msg["sender_id"] != user["user_id"] and msg["recipient_id"] != user["user_id"]:
        if user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Access denied")

    att = await db.message_attachments.find_one({"message_id": message_id}, {"_id": 0})
    if not att:
        raise HTTPException(status_code=404, detail="Attachment not found")

    if att.get("url"):
        return RedirectResponse(url=att["url"])

    file_data = base64.b64decode(att["data"])
    return Response(
        content=file_data,
        media_type=att["content_type"],
        headers={"Content-Disposition": f'attachment; filename="{att["filename"]}"'},
    )


@chat_router.put("/messages/mark-read/{recipient_id}")
async def mark_conversation_read(
    recipient_id: str, user: dict = Depends(get_current_user)
):
    """Mark all messages from a sender as read"""
    await db.user_messages.update_many(
        {"sender_id": recipient_id, "recipient_id": user["user_id"], "read": False},
        {"$set": {"read": True}},
    )
    asyncio.create_task(manager.send_to(recipient_id, {
        "type": "dm_read", "reader_id": user["user_id"],
    }))
    return {"message": "Messages marked as read"}


@chat_router.get("/messages")
async def get_messages(
    limit: int = 100,
    context_type: Optional[str] = None,
    user: dict = Depends(get_current_user),
):
    """Get internal messages (legacy endpoint)"""
    query = {}
    if context_type:
        query["context.type"] = context_type
    messages = (
        await db.internal_messages.find(query, {"_id": 0})
        .sort("created_at", -1)
        .to_list(limit)
    )
    return messages


@chat_router.post("/messages")
async def send_message(
    request: Request, data: dict = Body(...), user: dict = Depends(get_current_user)
):
    """Send an internal message (legacy endpoint)"""
    now = datetime.now(timezone.utc)
    message_id = f"msg_{uuid.uuid4().hex[:12]}"
    message_doc = {
        "message_id": message_id,
        "content": data.get("content", ""),
        "context": data.get("context"),
        "sender_id": user["user_id"],
        "sender_name": user["name"],
        "created_at": now.isoformat(),
        "read_by": [],
    }
    await db.internal_messages.insert_one(message_doc)
    return {"message": "Message sent", "message_id": message_id}


@chat_router.put("/messages/{message_id}/read")
async def mark_message_read(message_id: str, user: dict = Depends(get_current_user)):
    """Mark a message as read"""
    await db.internal_messages.update_one(
        {"message_id": message_id}, {"$addToSet": {"read_by": user["user_id"]}}
    )
    return {"message": "Message marked as read"}


@chat_router.get("/messages/admin/all-conversations")
async def get_all_conversations_admin(user: dict = Depends(get_current_user)):
    """Get all conversations in the system (admin only)"""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    pipeline = [
        {
            "$group": {
                "_id": {
                    "pair": {
                        "$cond": [
                            {"$lt": ["$sender_id", "$recipient_id"]},
                            ["$sender_id", "$recipient_id"],
                            ["$recipient_id", "$sender_id"],
                        ]
                    }
                },
                "message_count": {"$sum": 1},
                "last_message_at": {"$max": "$created_at"},
                "first_message_at": {"$min": "$created_at"},
            }
        },
        {"$sort": {"last_message_at": -1}},
    ]

    conversations = await db.user_messages.aggregate(pipeline).to_list(100)

    result = []
    for conv in conversations:
        pair = conv["_id"]["pair"]
        if len(pair) != 2:
            continue
        user1_id, user2_id = pair
        user1 = await db.users.find_one({"user_id": user1_id}, {"_id": 0, "name": 1, "email": 1})
        user2 = await db.users.find_one({"user_id": user2_id}, {"_id": 0, "name": 1, "email": 1})
        result.append(
            {
                "user1_id": user1_id,
                "user1_name": user1.get("name") if user1 else "Unknown",
                "user1_email": user1.get("email") if user1 else "",
                "user2_id": user2_id,
                "user2_name": user2.get("name") if user2 else "Unknown",
                "user2_email": user2.get("email") if user2 else "",
                "message_count": conv["message_count"],
                "last_message_at": conv["last_message_at"],
                "first_message_at": conv["first_message_at"],
            }
        )
    return result


@chat_router.get("/messages/admin/conversation/{user1_id}/{user2_id}")
async def get_conversation_messages_admin(
    user1_id: str, user2_id: str, user: dict = Depends(get_current_user)
):
    """Get all messages between two users (admin only)"""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    messages = (
        await db.user_messages.find(
            {
                "$or": [
                    {"sender_id": user1_id, "recipient_id": user2_id},
                    {"sender_id": user2_id, "recipient_id": user1_id},
                ]
            },
            {"_id": 0},
        )
        .sort("created_at", 1)
        .to_list(500)
    )

    user_cache = {}
    for msg in messages:
        sender_id = msg.get("sender_id")
        if sender_id not in user_cache:
            sender = await db.users.find_one({"user_id": sender_id}, {"_id": 0, "name": 1})
            user_cache[sender_id] = sender.get("name") if sender else "Unknown"
        msg["sender_name"] = user_cache[sender_id]

    return messages


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP CHANNELS
# ═══════════════════════════════════════════════════════════════════════════════

@chat_router.get("/channels")
async def get_channels(user: dict = Depends(get_current_user)):
    """Get all channels the current user is a member of"""
    user_id = user["user_id"]
    channels = await db.channels.find(
        {"members": user_id}, {"_id": 0}
    ).sort("created_at", 1).to_list(100)

    result = []
    for ch in channels:
        channel_id = ch["channel_id"]
        last_msg = await db.channel_messages.find_one(
            {"channel_id": channel_id, "thread_root_id": None},
            {"_id": 0},
            sort=[("created_at", -1)],
        )
        last_read_ts = ch.get("last_read", {}).get(user_id, "")
        if last_read_ts:
            unread_count = await db.channel_messages.count_documents({
                "channel_id": channel_id,
                "thread_root_id": None,
                "sender_id": {"$ne": user_id},
                "created_at": {"$gt": last_read_ts},
            })
        else:
            unread_count = await db.channel_messages.count_documents({
                "channel_id": channel_id,
                "thread_root_id": None,
                "sender_id": {"$ne": user_id},
            })
        result.append({
            **ch,
            "last_message": last_msg.get("content", "")[:60] if last_msg else "",
            "last_message_at": last_msg.get("created_at") if last_msg else ch.get("created_at"),
            "unread_count": unread_count,
        })
    return result


@chat_router.post("/channels")
async def create_channel(
    request: Request,
    data: dict = Body(...),
    user: dict = Depends(get_current_user),
):
    """Create a new group channel"""
    name = (data.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Channel name is required")

    channel_id = f"ch_{uuid.uuid4().hex[:12]}"
    members = list(set(data.get("members", []) + [user["user_id"]]))
    now = datetime.now(timezone.utc).isoformat()

    channel_doc = {
        "channel_id": channel_id,
        "name": name,
        "description": data.get("description", ""),
        "members": members,
        "created_by": user["user_id"],
        "created_by_name": user["name"],
        "created_at": now,
        "last_read": {},
    }
    await db.channels.insert_one(channel_doc)
    channel_doc.pop("_id", None)
    return channel_doc


@chat_router.patch("/channels/{channel_id}")
async def update_channel(
    channel_id: str,
    data: dict = Body(...),
    user: dict = Depends(get_current_user),
):
    """Edit channel name, description, or members"""
    channel = await db.channels.find_one({"channel_id": channel_id})
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    if user["user_id"] not in channel.get("members", []):
        raise HTTPException(status_code=403, detail="Not a member of this channel")

    update: dict = {}
    if data.get("name", "").strip():
        update["name"] = data["name"].strip()
    if "description" in data:
        update["description"] = data["description"]
    if "members" in data:
        update["members"] = list(set(data["members"] + [user["user_id"]]))

    if update:
        await db.channels.update_one({"channel_id": channel_id}, {"$set": update})

    updated = await db.channels.find_one({"channel_id": channel_id}, {"_id": 0})
    return updated


@chat_router.delete("/channels/{channel_id}")
async def delete_channel(
    channel_id: str,
    user: dict = Depends(get_current_user),
):
    """Delete a channel (creator only)"""
    channel = await db.channels.find_one({"channel_id": channel_id})
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    if channel.get("created_by") != user["user_id"] and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only the channel creator can delete it")
    await db.channels.delete_one({"channel_id": channel_id})
    await db.channel_messages.delete_many({"channel_id": channel_id})
    return {"message": "Channel deleted"}


@chat_router.post("/channels/{channel_id}/members")
async def add_channel_members(
    channel_id: str,
    data: dict = Body(...),
    user: dict = Depends(get_current_user),
):
    """Add members to a channel"""
    channel = await db.channels.find_one({"channel_id": channel_id})
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    if user["user_id"] not in channel.get("members", []):
        raise HTTPException(status_code=403, detail="Not a member of this channel")

    new_members = data.get("members", [])
    await db.channels.update_one(
        {"channel_id": channel_id},
        {"$addToSet": {"members": {"$each": new_members}}},
    )
    return {"message": "Members added"}


@chat_router.get("/channels/{channel_id}/messages")
async def get_channel_messages(
    channel_id: str,
    page: int = 1,
    page_size: int = 50,
    user: dict = Depends(get_current_user),
):
    """Get paginated messages for a channel (top-level only)"""
    channel = await db.channels.find_one({"channel_id": channel_id})
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    if user["user_id"] not in channel.get("members", []):
        raise HTTPException(status_code=403, detail="Not a member of this channel")

    skip = (page - 1) * page_size
    messages = (
        await db.channel_messages.find(
            {"channel_id": channel_id, "thread_root_id": None},
            {"_id": 0},
        )
        .sort("created_at", 1)
        .skip(skip)
        .to_list(page_size)
    )
    return messages


@chat_router.post("/channels/{channel_id}/messages")
async def send_channel_message(
    request: Request,
    channel_id: str,
    content: str = Form(""),
    files: List[UploadFile] = File(default=[]),
    user: dict = Depends(get_current_user),
):
    """Send a message with optional multiple file attachments to a channel"""
    channel = await db.channels.find_one({"channel_id": channel_id})
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    if user["user_id"] not in channel.get("members", []):
        raise HTTPException(status_code=403, detail="Not a member of this channel")

    if not content.strip() and not files:
        raise HTTPException(status_code=400, detail="Message or attachment required")

    now = datetime.now(timezone.utc).isoformat()
    msg_id = f"cmsg_{uuid.uuid4().hex[:12]}"

    attachments = []
    for f in files:
        if not f.filename:
            continue
        file_content = await f.read()
        ct = f.content_type or "application/octet-stream"
        max_size = 100 * 1024 * 1024 if ct.startswith("video/") else 20 * 1024 * 1024
        if len(file_content) > max_size:
            raise HTTPException(status_code=400, detail=f"{f.filename} exceeds size limit")
        url = upload_to_r2(file_content, f.filename, ct, "channel-media")
        attachments.append({
            "filename": f.filename,
            "content_type": ct,
            "size": len(file_content),
            "url": url,
        })

    msg_doc = {
        "msg_id": msg_id,
        "channel_id": channel_id,
        "sender_id": user["user_id"],
        "sender_name": user["name"],
        "content": content,
        "attachments": attachments,
        "thread_root_id": None,
        "reply_count": 0,
        "created_at": now,
    }
    await db.channel_messages.insert_one(msg_doc)
    msg_doc.pop("_id", None)
    asyncio.create_task(manager.broadcast(channel.get("members", []), {
        "type": "channel_message", "message": msg_doc, "channel_name": channel.get("name", ""),
    }))
    return msg_doc


# ═══════════════════════════════════════════════════════════════════════════════
# BUZZ  ("missed-call"-style attention ring)
# ═══════════════════════════════════════════════════════════════════════════════

# In-memory rate-limit: {f"{uid}:{scope}:{target}": datetime}
_last_buzz: dict = {}
BUZZ_COOLDOWN_SECONDS = 30


def _buzz_rate_ok(key: str, now: datetime):
    last = _last_buzz.get(key)
    if last and (now - last).total_seconds() < BUZZ_COOLDOWN_SECONDS:
        wait = int(BUZZ_COOLDOWN_SECONDS - (now - last).total_seconds()) + 1
        raise HTTPException(status_code=429, detail=f"Please wait {wait}s before buzzing again")
    _last_buzz[key] = now


@chat_router.post("/channels/{channel_id}/buzz")
async def buzz_channel(
    channel_id: str,
    data: dict = Body(default={}),
    user: dict = Depends(get_current_user),
):
    """Ring every other member of a channel like an incoming call."""
    channel = await db.channels.find_one({"channel_id": channel_id})
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    if user["user_id"] not in channel.get("members", []):
        raise HTTPException(status_code=403, detail="Not a member of this channel")

    now = datetime.now(timezone.utc)
    _buzz_rate_ok(f"{user['user_id']}:ch:{channel_id}", now)

    reason = (data.get("reason") or "").strip()[:200]
    buzz_id = f"buzz_{uuid.uuid4().hex[:12]}"
    members = channel.get("members", [])
    others = [m for m in members if m != user["user_id"]]

    # System line doubles as the missed-call record in the channel history
    sys_msg = {
        "msg_id": f"cmsg_{uuid.uuid4().hex[:12]}",
        "channel_id": channel_id,
        "sender_id": user["user_id"],
        "sender_name": user["name"],
        "content": f"📞 {user['name']} buzzed the channel" + (f": {reason}" if reason else ""),
        "attachments": [],
        "thread_root_id": None,
        "reply_count": 0,
        "created_at": now.isoformat(),
        "is_buzz": True,
    }
    await db.channel_messages.insert_one(sys_msg)
    sys_msg.pop("_id", None)

    asyncio.create_task(manager.broadcast(others, {
        "type": "buzz",
        "scope": "channel",
        "buzz_id": buzz_id,
        "channel_id": channel_id,
        "channel_name": channel.get("name", ""),
        "from_id": user["user_id"],
        "from_name": user["name"],
        "reason": reason,
    }))
    asyncio.create_task(manager.broadcast(members, {
        "type": "channel_message", "message": sys_msg, "channel_name": channel.get("name", ""),
    }))
    return {"success": True, "buzz_id": buzz_id, "notified": len(others)}


@chat_router.post("/messages/{recipient_id}/buzz")
async def buzz_dm(
    recipient_id: str,
    data: dict = Body(default={}),
    user: dict = Depends(get_current_user),
):
    """Ring a single user like an incoming call (direct message)."""
    recipient = await db.users.find_one({"user_id": recipient_id})
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    now = datetime.now(timezone.utc)
    _buzz_rate_ok(f"{user['user_id']}:dm:{recipient_id}", now)

    reason = (data.get("reason") or "").strip()[:200]
    buzz_id = f"buzz_{uuid.uuid4().hex[:12]}"

    sys_msg = {
        "message_id": f"msg_{uuid.uuid4().hex[:12]}",
        "sender_id": user["user_id"],
        "sender_name": user["name"],
        "recipient_id": recipient_id,
        "recipient_name": recipient.get("name", "Unknown"),
        "content": f"📞 {user['name']} buzzed you" + (f": {reason}" if reason else ""),
        "attachment": None,
        "read": False,
        "created_at": now.isoformat(),
        "is_buzz": True,
    }
    await db.user_messages.insert_one(sys_msg)
    sys_msg.pop("_id", None)

    asyncio.create_task(manager.broadcast([recipient_id], {
        "type": "buzz",
        "scope": "dm",
        "buzz_id": buzz_id,
        "dm_peer_id": user["user_id"],       # recipient opens the conversation with the buzzer
        "dm_peer_name": user["name"],
        "from_id": user["user_id"],
        "from_name": user["name"],
        "reason": reason,
    }))
    asyncio.create_task(manager.broadcast([recipient_id, user["user_id"]], {
        "type": "dm_message", "message": sys_msg,
    }))
    return {"success": True, "buzz_id": buzz_id}


@chat_router.post("/buzz/ack")
async def ack_buzz(
    data: dict = Body(default={}),
    user: dict = Depends(get_current_user),
):
    """Tell the buzzer that their ring was answered or declined."""
    from_id = data.get("from_id")
    action = data.get("action")
    if not from_id or action not in ("answered", "declined"):
        raise HTTPException(status_code=400, detail="from_id and action required")
    asyncio.create_task(manager.broadcast([from_id], {
        "type": "buzz_ack",
        "action": action,
        "by_id": user["user_id"],
        "by_name": user["name"],
        "scope": data.get("scope", ""),
        "channel_name": data.get("channel_name", ""),
    }))
    return {"success": True}


@chat_router.get("/channels/{channel_id}/messages/{msg_id}/replies")
async def get_thread_replies(
    channel_id: str,
    msg_id: str,
    user: dict = Depends(get_current_user),
):
    """Get all replies in a message thread"""
    channel = await db.channels.find_one({"channel_id": channel_id})
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    if user["user_id"] not in channel.get("members", []):
        raise HTTPException(status_code=403, detail="Not a member of this channel")

    replies = (
        await db.channel_messages.find(
            {"channel_id": channel_id, "thread_root_id": msg_id},
            {"_id": 0},
        )
        .sort("created_at", 1)
        .to_list(200)
    )
    return replies


@chat_router.post("/channels/{channel_id}/messages/{msg_id}/replies")
async def send_thread_reply(
    request: Request,
    channel_id: str,
    msg_id: str,
    content: str = Form(""),
    files: List[UploadFile] = File(default=[]),
    user: dict = Depends(get_current_user),
):
    """Send a reply in a message thread"""
    channel = await db.channels.find_one({"channel_id": channel_id})
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    if user["user_id"] not in channel.get("members", []):
        raise HTTPException(status_code=403, detail="Not a member of this channel")

    parent = await db.channel_messages.find_one({"msg_id": msg_id, "channel_id": channel_id})
    if not parent:
        raise HTTPException(status_code=404, detail="Message not found")

    if not content.strip() and not files:
        raise HTTPException(status_code=400, detail="Reply content or attachment required")

    now = datetime.now(timezone.utc).isoformat()
    reply_id = f"cmsg_{uuid.uuid4().hex[:12]}"

    attachments = []
    for f in files:
        if not f.filename:
            continue
        file_content = await f.read()
        ct = f.content_type or "application/octet-stream"
        max_size = 100 * 1024 * 1024 if ct.startswith("video/") else 20 * 1024 * 1024
        if len(file_content) > max_size:
            raise HTTPException(status_code=400, detail=f"{f.filename} exceeds size limit")
        url = upload_to_r2(file_content, f.filename, ct, "channel-media")
        attachments.append({
            "filename": f.filename,
            "content_type": ct,
            "size": len(file_content),
            "url": url,
        })

    reply_doc = {
        "msg_id": reply_id,
        "channel_id": channel_id,
        "sender_id": user["user_id"],
        "sender_name": user["name"],
        "content": content,
        "attachments": attachments,
        "thread_root_id": msg_id,
        "created_at": now,
    }
    await db.channel_messages.insert_one(reply_doc)
    await db.channel_messages.update_one(
        {"msg_id": msg_id}, {"$inc": {"reply_count": 1}}
    )
    reply_doc.pop("_id", None)
    asyncio.create_task(manager.broadcast(channel.get("members", []), {
        "type": "thread_reply", "message": reply_doc, "parent_sender_id": parent["sender_id"],
    }))
    return reply_doc


@chat_router.put("/channels/{channel_id}/mark-read")
async def mark_channel_read(
    channel_id: str,
    user: dict = Depends(get_current_user),
):
    """Update the user's last-read timestamp for a channel"""
    now = datetime.now(timezone.utc).isoformat()
    await db.channels.update_one(
        {"channel_id": channel_id},
        {"$set": {f"last_read.{user['user_id']}": now}},
    )
    return {"message": "Marked as read"}


# ── Message edit / delete ───────────────────────────────────────────────────
@chat_router.put("/messages/{message_id}")
async def edit_user_message(
    message_id: str, request: Request, user: dict = Depends(get_current_user)
):
    """Edit a direct message (sender only)."""
    data = await request.json()
    content = (data.get("content") or "").strip()
    msg = await db.user_messages.find_one({"message_id": message_id})
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    if msg.get("sender_id") != user["user_id"]:
        raise HTTPException(status_code=403, detail="You can only edit your own messages")
    if msg.get("deleted"):
        raise HTTPException(status_code=400, detail="Cannot edit a deleted message")
    if not content and not msg.get("attachment"):
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    now = datetime.now(timezone.utc).isoformat()
    await db.user_messages.update_one(
        {"message_id": message_id},
        {"$set": {"content": content, "edited": True, "edited_at": now}},
    )
    updated = await db.user_messages.find_one({"message_id": message_id}, {"_id": 0})
    asyncio.create_task(
        manager.broadcast(
            [msg["recipient_id"], msg["sender_id"]],
            {"type": "dm_edit", "message": updated},
        )
    )
    return updated


@chat_router.delete("/messages/{message_id}")
async def delete_user_message(
    message_id: str, user: dict = Depends(get_current_user)
):
    """Soft-delete a direct message (sender, or any admin)."""
    msg = await db.user_messages.find_one({"message_id": message_id})
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    if msg.get("sender_id") != user["user_id"] and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="You can only delete your own messages")
    now = datetime.now(timezone.utc).isoformat()
    await db.user_messages.update_one(
        {"message_id": message_id},
        {"$set": {
            "deleted": True, "deleted_at": now, "deleted_by": user["user_id"],
            "content": "", "attachment": None,
        }},
    )
    updated = await db.user_messages.find_one({"message_id": message_id}, {"_id": 0})
    asyncio.create_task(
        manager.broadcast(
            [msg["recipient_id"], msg["sender_id"]],
            {"type": "dm_delete", "message": updated},
        )
    )
    return {"success": True, "message_id": message_id}


@chat_router.put("/channels/{channel_id}/messages/{msg_id}")
async def edit_channel_message(
    channel_id: str, msg_id: str, request: Request, user: dict = Depends(get_current_user)
):
    """Edit a channel message (sender only)."""
    data = await request.json()
    content = (data.get("content") or "").strip()
    msg = await db.channel_messages.find_one({"msg_id": msg_id, "channel_id": channel_id})
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    if msg.get("sender_id") != user["user_id"]:
        raise HTTPException(status_code=403, detail="You can only edit your own messages")
    if msg.get("deleted"):
        raise HTTPException(status_code=400, detail="Cannot edit a deleted message")
    if not content and not msg.get("attachments"):
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    now = datetime.now(timezone.utc).isoformat()
    await db.channel_messages.update_one(
        {"msg_id": msg_id},
        {"$set": {"content": content, "edited": True, "edited_at": now}},
    )
    updated = await db.channel_messages.find_one({"msg_id": msg_id}, {"_id": 0})
    channel = await db.channels.find_one({"channel_id": channel_id})
    asyncio.create_task(
        manager.broadcast(
            (channel or {}).get("members", []),
            {"type": "channel_edit", "message": updated},
        )
    )
    return updated


@chat_router.delete("/channels/{channel_id}/messages/{msg_id}")
async def delete_channel_message(
    channel_id: str, msg_id: str, user: dict = Depends(get_current_user)
):
    """Soft-delete a channel message (sender, or any admin)."""
    msg = await db.channel_messages.find_one({"msg_id": msg_id, "channel_id": channel_id})
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    if msg.get("sender_id") != user["user_id"] and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="You can only delete your own messages")
    now = datetime.now(timezone.utc).isoformat()
    await db.channel_messages.update_one(
        {"msg_id": msg_id},
        {"$set": {
            "deleted": True, "deleted_at": now, "deleted_by": user["user_id"],
            "content": "", "attachments": [],
        }},
    )
    updated = await db.channel_messages.find_one({"msg_id": msg_id}, {"_id": 0})
    channel = await db.channels.find_one({"channel_id": channel_id})
    asyncio.create_task(
        manager.broadcast(
            (channel or {}).get("members", []),
            {"type": "channel_delete", "message": updated},
        )
    )
    return {"success": True, "msg_id": msg_id}


# ── Transaction-request auto-notifications (#deposite_only / #withdraw_only) ──
TX_CHANNELS = {"deposit": "deposite_only", "withdrawal": "withdraw_only"}
TX_BOT_ID = "user_txbot"
TX_BOT_NAME = "Transactions"


async def _ensure_tx_bot():
    """Ensure the 'Transactions' system user exists so it can DM request creators."""
    existing = await db.users.find_one({"user_id": TX_BOT_ID}, {"_id": 0, "user_id": 1})
    if not existing:
        await db.users.insert_one({
            "user_id": TX_BOT_ID,
            "name": TX_BOT_NAME,
            "email": "tx-bot@system.local",
            "role": "system",
            "is_active": True,
            "is_system": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })


async def ensure_tx_channels():
    """Create the default #deposite_only / #withdraw_only channels if missing and
    keep every super-admin / admin as a member. Idempotent — safe on every startup."""
    try:
        await _ensure_tx_bot()
        admins = await db.users.find(
            {"role": {"$in": ["super_admin", "admin"]}}, {"_id": 0, "user_id": 1}
        ).to_list(1000)
        member_ids = [u["user_id"] for u in admins if u.get("user_id")]
        now = datetime.now(timezone.utc).isoformat()
        for cname in TX_CHANNELS.values():
            existing = await db.channels.find_one({"name": cname})
            if existing:
                merged = list(set(existing.get("members", []) + member_ids))
                if set(merged) != set(existing.get("members", [])):
                    await db.channels.update_one(
                        {"channel_id": existing["channel_id"]}, {"$set": {"members": merged}}
                    )
                continue
            await db.channels.insert_one({
                "channel_id": f"chan_{uuid.uuid4().hex[:12]}",
                "name": cname,
                "description": f"Auto-posted {cname.split('_')[0]} transaction requests",
                "members": member_ids,
                "created_by": "system",
                "created_by_name": "System",
                "created_at": now,
                "last_read": {},
                "system_channel": True,
            })
    except Exception as e:
        print(f"ensure_tx_channels failed: {e}")


def _fmt_amt(cur, amt):
    try:
        return f"{cur or 'USD'} {float(amt or 0):,.2f}"
    except Exception:
        return f"{cur or 'USD'} {amt}"


def _tx_bank_block(req: dict) -> dict:
    """Client bank/USDT details for a withdrawal card (only non-empty fields)."""
    b = {
        "account_name": req.get("client_bank_account_name"),
        "bank_name": req.get("client_bank_name"),
        "account_number": req.get("client_bank_account_number"),
        "swift_iban": req.get("client_bank_swift_iban"),
        "branch": req.get("client_bank_branch"),
        "currency": req.get("client_bank_currency"),
        "usdt_address": req.get("client_usdt_address"),
        "usdt_network": req.get("client_usdt_network"),
    }
    b = {k: v for k, v in b.items() if v}
    return b or None


def _render_tx_card(comp: dict) -> str:
    """Build the card text from stored components (reused on post + edit)."""
    lines = []
    if comp.get("crm"):
        lines.append(str(comp["crm"]))
    if comp.get("client_name"):
        lines.append(comp["client_name"])
    if comp.get("email"):
        lines.append(comp["email"])
    lines.append(_fmt_amt(comp.get("currency", "USD"), comp.get("amount")))
    if comp.get("base_currency") and comp["base_currency"] != "USD" and comp.get("base_amount"):
        lines.append(_fmt_amt(comp["base_currency"], comp["base_amount"]))
    if comp.get("dest"):
        lines.append(comp["dest"])
    bank = comp.get("bank") or {}
    if bank:
        lines.append("——")
        labels = [("account_name", "A/C Name"), ("bank_name", "Bank"), ("account_number", "A/C No"),
                  ("swift_iban", "IBAN/SWIFT"), ("branch", "Branch"), ("currency", "Currency"),
                  ("usdt_address", "USDT"), ("usdt_network", "Network")]
        for key, lbl in labels:
            if bank.get(key):
                lines.append(f"{lbl}: {bank[key]}")
    return "\n".join(lines)


async def _resolve_tx_dest(req: dict) -> str:
    dest = ""
    if req.get("destination_account_id"):
        acc = await db.treasury_accounts.find_one(
            {"account_id": req["destination_account_id"]}, {"_id": 0, "account_name": 1})
        dest = (acc or {}).get("account_name", "")
    if not dest and req.get("psp_id"):
        psp = await db.psps.find_one({"psp_id": req["psp_id"]}, {"_id": 0, "psp_name": 1})
        dest = (psp or {}).get("psp_name", "")
    if not dest and req.get("vendor_id"):
        ven = await db.vendors.find_one({"vendor_id": req["vendor_id"]}, {"_id": 0, "vendor_name": 1})
        dest = (ven or {}).get("vendor_name", "")
    return dest


async def post_tx_request_notification(req: dict, client: dict, proof_url: str = None):
    """Post a transaction-request card to #deposite_only / #withdraw_only AND DM the
    request creator. Never raises — notification failures must not break request creation."""
    try:
        ttype = req.get("transaction_type")
        cname = TX_CHANNELS.get(ttype)
        if not cname:
            return
        channel = await db.channels.find_one({"name": cname})
        if not channel:
            return

        comp = {
            "crm": req.get("crm_reference") or req.get("reference"),
            "client_name": req.get("client_name"),
            "email": (client or {}).get("email"),
            "currency": req.get("currency", "USD"),
            "amount": req.get("amount"),
            "base_currency": req.get("base_currency"),
            "base_amount": req.get("base_amount"),
            "dest": await _resolve_tx_dest(req),
            "bank": _tx_bank_block(req) if ttype == "withdrawal" else None,
        }
        ref = req.get("crm_reference") or req.get("reference")
        attachments = []
        if proof_url:
            attachments.append({"filename": "proof.png", "content_type": "image/png", "url": proof_url})
        now_iso = datetime.now(timezone.utc).isoformat()
        common = {
            "content": _render_tx_card(comp), "attachments": attachments,
            "is_tx_bot": True, "tx_request_id": req.get("request_id"),
            "tx_reference": ref, "tx_type": ttype, "tx_status": "pending",
            "tx_comp": comp, "tx_owner_id": req.get("created_by"),
        }

        # 1) Channel card (admins act on it)
        msg_doc = {
            "msg_id": f"cmsg_{uuid.uuid4().hex[:12]}",
            "channel_id": channel["channel_id"],
            "sender_id": req.get("created_by", "system"),
            "sender_name": req.get("created_by_name") or "System",
            "thread_root_id": None, "reply_count": 0, "created_at": now_iso,
            **common,
        }
        await db.channel_messages.insert_one(msg_doc)
        msg_doc.pop("_id", None)
        asyncio.create_task(manager.broadcast(channel.get("members", []), {
            "type": "channel_message", "message": msg_doc, "channel_name": channel.get("name", ""),
        }))

        # 2) DM card to the creator (so they can track their own request's status)
        creator = req.get("created_by")
        if creator and creator != TX_BOT_ID:
            await _ensure_tx_bot()
            dm_doc = {
                "message_id": f"msg_{uuid.uuid4().hex[:12]}",
                "sender_id": TX_BOT_ID, "sender_name": TX_BOT_NAME,
                "recipient_id": creator, "recipient_name": req.get("created_by_name") or "",
                "attachment": (attachments[0] if attachments else None),
                "read": False, "created_at": now_iso,
                **common,
            }
            await db.user_messages.insert_one(dm_doc)
            dm_doc.pop("_id", None)
            asyncio.create_task(manager.broadcast([creator], {
                "type": "dm_message", "message": dm_doc,
            }))
    except Exception as e:
        print(f"post_tx_request_notification failed: {e}")


async def _update_tx_cards(request_id: str, set_fields: dict):
    """Apply set_fields to EVERY channel + creator-DM card for a request_id (unique,
    N/A-safe) and broadcast the edits so all clients update live."""
    if not request_id:
        return
    for cmsg in await db.channel_messages.find({"is_tx_bot": True, "tx_request_id": request_id}, {"_id": 0}).to_list(20):
        await db.channel_messages.update_one({"msg_id": cmsg["msg_id"]}, {"$set": set_fields})
        updated = await db.channel_messages.find_one({"msg_id": cmsg["msg_id"]}, {"_id": 0})
        channel = await db.channels.find_one({"channel_id": cmsg["channel_id"]})
        asyncio.create_task(manager.broadcast((channel or {}).get("members", []), {
            "type": "channel_edit", "message": updated,
        }))
    for dmsg in await db.user_messages.find({"is_tx_bot": True, "tx_request_id": request_id}, {"_id": 0}).to_list(20):
        await db.user_messages.update_one({"message_id": dmsg["message_id"]}, {"$set": set_fields})
        updated = await db.user_messages.find_one({"message_id": dmsg["message_id"]}, {"_id": 0})
        asyncio.create_task(manager.broadcast(
            [dmsg.get("recipient_id"), dmsg.get("sender_id")],
            {"type": "dm_edit", "message": updated}))


async def post_tx_processed_notification(req: dict, processor_id: str, processor_name: str):
    """When a request is PROCESSED: mark its cards processed and DM the creator. Never raises."""
    try:
        request_id = req.get("request_id")
        ref = req.get("crm_reference") or req.get("reference")
        now_iso = datetime.now(timezone.utc).isoformat()
        # flip the deposit/withdraw + DM cards to processed
        await _update_tx_cards(request_id, {
            "tx_processed_by": processor_id, "tx_processed_by_name": processor_name,
            "tx_processed_at": now_iso,
        })
        # DM the request creator that it's been processed
        creator = req.get("created_by")
        if creator and creator != TX_BOT_ID:
            await _ensure_tx_bot()
            dm = {
                "message_id": f"msg_{uuid.uuid4().hex[:12]}",
                "sender_id": TX_BOT_ID, "sender_name": TX_BOT_NAME,
                "recipient_id": creator, "recipient_name": req.get("created_by_name") or "",
                "content": f"🟢 Your {req.get('transaction_type')} request {ref} was processed by {processor_name}.",
                "attachment": None, "read": False, "created_at": now_iso,
            }
            await db.user_messages.insert_one(dm)
            dm.pop("_id", None)
            asyncio.create_task(manager.broadcast([creator], {"type": "dm_message", "message": dm}))
    except Exception as e:
        print(f"post_tx_processed_notification failed: {e}")


async def set_tx_message_status(request_id: str, status: str, transaction_id: str = None):
    """Flip the linked channel + creator-DM cards to approved/rejected (keyed by request_id)."""
    try:
        if not request_id:
            return
        upd = {"tx_status": status}
        if transaction_id:
            upd["tx_transaction_id"] = transaction_id
        await _update_tx_cards(request_id, upd)
    except Exception as e:
        print(f"set_tx_message_status failed: {e}")


async def update_tx_message_content(request_id: str, changes: dict, new_crm: str = None):
    """Reflect a transaction/request edit on the cards (keyed by request_id): merge changed
    components, re-render the text, and update the CRM ref shown if it changed."""
    try:
        if not request_id:
            return
        cmsg = await db.channel_messages.find_one(
            {"is_tx_bot": True, "tx_request_id": request_id}, {"_id": 0})
        comp = dict((cmsg or {}).get("tx_comp") or {})
        if not comp:
            return
        comp.update({k: v for k, v in changes.items() if v is not None})
        if new_crm:
            comp["crm"] = new_crm
        set_fields = {"content": _render_tx_card(comp), "tx_comp": comp}
        if new_crm:
            set_fields["tx_reference"] = new_crm
        await _update_tx_cards(request_id, set_fields)
    except Exception as e:
        print(f"update_tx_message_content failed: {e}")


@chat_router.post("/chat/tx-complete")
async def tx_complete(data: dict = Body(...), user: dict = Depends(get_current_user)):
    """Owner-only: mark a transaction card complete and post a completion reply in the
    channel thread. Does NOT change the transaction — chat is notes/replies only."""
    request_id = (data.get("request_id") or "").strip()
    note = (data.get("note") or "").strip()[:500]
    if not request_id:
        raise HTTPException(status_code=400, detail="request_id required")
    card = await db.channel_messages.find_one({"is_tx_bot": True, "tx_request_id": request_id}, {"_id": 0})
    if not card:
        raise HTTPException(status_code=404, detail="Card not found")
    if card.get("tx_owner_id") and card["tx_owner_id"] != user["user_id"]:
        raise HTTPException(status_code=403, detail="Only the request owner can complete this")
    now = datetime.now(timezone.utc).isoformat()
    # 1) completion reply in the card's channel thread
    reply = {
        "msg_id": f"cmsg_{uuid.uuid4().hex[:12]}",
        "channel_id": card["channel_id"],
        "sender_id": user["user_id"], "sender_name": user["name"],
        "content": "✅ Completed" + (f" — {note}" if note else ""),
        "attachments": [], "thread_root_id": card["msg_id"], "reply_count": 0,
        "created_at": now,
    }
    await db.channel_messages.insert_one(reply)
    reply.pop("_id", None)
    await db.channel_messages.update_one({"msg_id": card["msg_id"]}, {"$inc": {"reply_count": 1}})
    # 2) mark the channel + DM cards completed
    await _update_tx_cards(request_id, {
        "tx_completed_by": user["user_id"], "tx_completed_by_name": user["name"],
        "tx_completed_at": now, "tx_completed_note": note,
    })
    # 3) flag the underlying transaction (Transactions Summary "Completed" column)
    await db.transactions.update_one(
        {"request_id": request_id},
        {"$set": {"completed": True, "completed_by": user["user_id"],
                  "completed_by_name": user["name"], "completed_at": now}})
    # 4) broadcast the thread reply
    channel = await db.channels.find_one({"channel_id": card["channel_id"]})
    asyncio.create_task(manager.broadcast((channel or {}).get("members", []), {
        "type": "thread_reply", "message": reply,
        "channel_id": card["channel_id"], "thread_root_id": card["msg_id"],
        "parent_sender_id": card.get("sender_id"),
    }))
    return {"success": True, "msg_id": reply["msg_id"]}
