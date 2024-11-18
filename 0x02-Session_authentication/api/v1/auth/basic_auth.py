#!/usr/bin/env python3
"""Basic Auth class file that inherit from Auth"""
from api.v1.auth.auth import Auth
import base64
from typing import Tuple, TypeVar
from models.user import User


class BasicAuth(Auth):
    """BasicAuth class"""

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """base64 auto header"""
        if authorization_header is None:
            return None
        if type(authorization_header) is not str:
            return None
        if authorization_header[:5] != "Basic":
            return None
        if authorization_header[5] != " ":
            return None
        return (authorization_header.split(" "))[1]

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str) -> str:
        """ decode the autorization header to base64"""
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) is not str:
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except BaseException:
            return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str
    ) -> (str, str):
        """extract user credential that has been decoded"""
        if decoded_base64_authorization_header is None:
            return (None, None)
        if type(decoded_base64_authorization_header) is not str:
            return (None, None)
        if ":" not in decoded_base64_authorization_header:
            return (None, None)
        val = decoded_base64_authorization_header.split(":", 1)
        return (val[0], val[1])

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str
    ) -> TypeVar('User'):
        """create user object from username and password"""
        if user_email is None or type(user_email) is not str:
            return None
        if user_pwd is None or type(user_pwd) is not str:
            return None
        try:
            users = User.search({'email': user_email})
        except Exception:
            return None

        for user in users:
            if user.is_valid_password(user_pwd):
                return user

        return None

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str
    ) -> TypeVar('User'):
        """method to return user object based on the password and username"""
        if user_email is None or type(user_email) is not str:
            return None
        if user_pwd is None or type(user_pwd) is not str:
            return None
        try:
            users = User.search({'email': user_email})
        except Exception:
            return None

        for user in users:
            if user.is_valid_password(user_pwd):
                return user

        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """returns the current user object after verification"""
        try:
            auth_header = self.authorization_header(request)
            extrac_header = self.extract_base64_authorization_header(
                auth_header)
            decoded = self.decode_base64_authorization_header(extrac_header)
            email, pwd = self.extract_user_credentials(decoded)
            return self.user_object_from_credentials(email, pwd)
        except Exception:
            return None
