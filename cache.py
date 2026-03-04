"""
Redis caching utility for API responses
"""
import json
import redis
import os
from functools import wraps
from typing import Optional, Any
import hashlib

# Redis connection
REDIS_URL = os.environ.get(
    'REDIS_URL',
    'redis://:YOUR_STRONG_PASSWORD@localhost:6379/0'
)
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

# Cache TTL in seconds
CACHE_TTL = {
    'vendors': 60,           # 1 minute
    'vendors_list': 30,      # 30 seconds
    'income_expenses': 30,   # 30 seconds
    'transactions': 30,      # 30 seconds
    'loans': 60,             # 1 minute
    'treasury': 60,          # 1 minute
    'clients': 60,           # 1 minute
    'dashboard': 30,         # 30 seconds
    'fx_rates': 300,         # 5 minutes
    'default': 30,           # 30 seconds default
}

def get_cache_key(prefix: str, *args, **kwargs) -> str:
    """Generate a unique cache key"""
    key_parts = [prefix]
    for arg in args:
        key_parts.append(str(arg))
    for k, v in sorted(kwargs.items()):
        if v is not None:
            key_parts.append(f"{k}:{v}")
    key_string = ":".join(key_parts)
    # Use hash for long keys
    if len(key_string) > 200:
        return f"{prefix}:{hashlib.md5(key_string.encode()).hexdigest()}"
    return key_string

def get_cached(key: str) -> Optional[Any]:
    """Get value from cache"""
    try:
        value = redis_client.get(key)
        if value:
            return json.loads(value)
    except Exception as e:
        print(f"Cache get error: {e}")
    return None

def set_cached(key: str, value: Any, ttl: int = None) -> bool:
    """Set value in cache"""
    try:
        ttl = ttl or CACHE_TTL['default']
        redis_client.setex(key, ttl, json.dumps(value, default=str))
        return True
    except Exception as e:
        print(f"Cache set error: {e}")
    return False

def invalidate_cache(pattern: str) -> int:
    """Invalidate cache keys matching pattern"""
    try:
        keys = redis_client.keys(pattern)
        if keys:
            return redis_client.delete(*keys)
    except Exception as e:
        print(f"Cache invalidate error: {e}")
    return 0

def invalidate_vendor_cache(vendor_id: str = None):
    """Invalidate vendor-related caches"""
    patterns = ['vendors:*', 'vendor:*']
    if vendor_id:
        patterns.append(f'vendor:{vendor_id}:*')
    for pattern in patterns:
        invalidate_cache(pattern)

def invalidate_ie_cache():
    """Invalidate income/expense caches"""
    invalidate_cache('ie:*')
    invalidate_cache('income_expenses:*')

def invalidate_transaction_cache():
    """Invalidate transaction caches"""
    invalidate_cache('transactions:*')
    invalidate_cache('tx:*')

def invalidate_loan_cache():
    """Invalidate loan caches"""
    invalidate_cache('loans:*')
    invalidate_cache('loan:*')

def invalidate_treasury_cache():
    """Invalidate treasury caches"""
    invalidate_cache('treasury:*')

def invalidate_all_cache():
    """Invalidate all caches"""
    try:
        redis_client.flushdb()
    except Exception as e:
        print(f"Cache flush error: {e}")

# Health check
def is_redis_available() -> bool:
    """Check if Redis is available"""
    try:
        return redis_client.ping()
    except:
        return False
