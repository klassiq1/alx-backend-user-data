#!/usr/bin/env python3
"""new model class that inherit from base to handle storing
of session in database
"""
from models.base import Base


class UserSession(Base):
    """the class begins"""

    def __init__(self, *args: list, **kwargs: dict):
        """init tins"""
        super().__init__(*args, **kwargs)
        self.user_id = kwargs.get('user_id')
        self.session_id = kwargs.get('session_id')
