import bcrypt

def hash_password(password: str) -> bytes:
    """
    hashes a password using bcrypt with automatic salting.
    returns the hashed password.
    """
    password_bytes = password.encode("utf-8")
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed


def verify_password(password: str, hashed_password: bytes) -> bool:
    """
    verifies a password against a stored bcrypt hash.
    """
    password_bytes = password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_password)
