
#!/usr/bin/env python3
"""auth file"""
from flask import request
from typing import List, TypeVar


class Auth:
    """Auth class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """require auth method - that returns False - path and excluded_paths
        will be used later, now, you don’t need to take care of them"""
        if path is None:
            return True
        if excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path in excluded_paths:
            return False
        if (path + "/") in excluded_paths:
            return False
        if (path[:-1]) in excluded_paths:
            return False
        for b in excluded_paths:
            if "*" in b:
                rout = b.split("*")
                if path.startswith(rout[0]):
                    return False
                rout = []
        return True

    def authorization_header(self, request=None) -> str:
        """returns None - request will be the Flask request object"""
        if request is None:
            return None
        headd = request.headers.get('Authorization')
        if headd:
            return headd
        else:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """that returns None - request will be the Flask request object"""
        return None

