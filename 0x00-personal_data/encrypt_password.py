#!/usr/bin/env python3
"""module encrypting passwords
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """hashe password using random salt
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """checks hashed password formed from given password
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
