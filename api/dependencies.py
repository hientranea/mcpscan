from shared.db.redis_client import redis_client


def get_redis_client():
    """Dependency for Redis client"""
    return redis_client
