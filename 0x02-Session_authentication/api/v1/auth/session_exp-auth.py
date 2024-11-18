#!/usr/bin/env python3
""" class to create expiration for session
"""
import os
import datetime
from flask import request
from api.v1.auth.session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """the class begins"""

    def __init__(self):
        """initializing the class"""

        sess_dur = os.getenv("SESSION_DURATION")
        if sess_dur is None:
            self.session_duration = 0
        else:
            try:
                sess_val = int(sess_dur)
                self.session_duration = sess_val
            except Exception:
                self.session_duration = 0

    def create_session(self, user_id=None):
        """overloaded method to creat session with super()"""
        sess_id = super().create_session(user_id)
        if sess_id is None or type(sess_id) is not str:
            return None
        self.user_id_by_session_id[sess_id] = {
            "user_id": user_id,
            "created_at": datetime.datetime.now()
            }
        return sess_id

    def user_id_for_session_id(self, session_id=None):
        """overload the user_id_for_session_id to give out user_id"""
        if session_id is None:
            return None
        usr_dt = self.user_id_by_session_id.get(session_id)
        if usr_dt is None:
            return None
        if usr_dt.get("created_at") is None:
            return None
        if self.session_duration <= 0:
            usr_id = usr_dt.get("user_id")
            return usr_id
        cur_time = datetime.datetime.now()
        time_span = datetime.timedelta(seconds=self.session_duration)
        exp_time = usr_dt['created_at'] + time_span
        if exp_time < cur_time:
            return None
        return usr_dt['user_id']
