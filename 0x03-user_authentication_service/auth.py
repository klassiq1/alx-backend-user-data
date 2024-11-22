#!/usr/bin/env python3
"""A module for authentication-related routines.
"""
import bcrypt
from uuid import uuid4
from typing import Union
from sqlalchemy.orm.exc import NoResultFound
from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """Hashes a password.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def _generate_uuid() -> str:
    """generate a uuid for return"""
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """method to hash pwd, create user and return user"""
        hsh_pwd = _hash_password(password)
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, hsh_pwd)
        raise ValueError("User " + email + " already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """validate a login given email and pwd"""
        try:
            usr = self._db.find_user_by(email=email)
            if bcrypt.checkpw(password.encode(
                    "utf-8"), usr.hashed_password):
                return True
            else:
                return False
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """create a session for an email"""
        try:
            usr = self._db.find_user_by(email=email)
            uid = _generate_uuid()
            self._db.update_user(usr.id, session_id=uid)
            return uid
        except NoResultFound:
            return None
        return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """return a user based on a session_id"""
        if session_id is None:
            return None
        try:
            usr = self._db.find_user_by(session_id=session_id)
            return usr
        except NoResultFound:
            return None

    def destroy_session(self, user_id: str) -> None:
        """destroy the session by changing the
session in db to none"""
        if user_id is None:
            return None
        try:
            usr = self._db.find_user_by(id=user_id)
            self._db.update_user(usr.id, session_id=None)
            return None
        except NoResultFound:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """get a reset password token for an email"""
        try:
            usr = self._db.find_user_by(email=email)
            uid = _generate_uuid()
            self._db.update_user(usr.id, reset_token=uid)
            return uid
        except NoResultFound:
            raise ValueError
        return None

    def update_password(self, reset_token: str, password: str) -> None:
        """update password via reset token"""
        try:
            usr = self._db.find_user_by(reset_token=reset_token)
            hsh_pw = _hash_password(password)
            self._db.update_user(
                usr.id, hashed_password=hsh_pw, reset_token=None)
            return None
        except NoResultFound:
            raise ValueError
