#!/usr/bin/env python3
""" class to handle session and store the session in database
"""
import os
import datetime
from flask import request
from models.user_session import UserSession
from api.v1.auth.session_exp_auth import SessionExpAuth


class SessionDBAuth(SessionExpAuth):
    """the class begins"""

    def create_session(self, user_id=None):
        """overloaded method to creat session with super() for
database handling"""
        sess_id = super().create_session(user_id)
        if sess_id is None or type(sess_id) is not str:
            return None
        kwargs = {
            "user_id": user_id,
            "session_id": sess_id
            }
        usr_sess_obj = UserSession(**kwargs)
        usr_sess_obj.save()
        return sess_id

    def user_id_for_session_id(self, session_id=None):
        """overload the user_id_for_session_id to give out
user_id from the database"""
        if session_id is None:
            return None
        try:
            usr_dt = UserSession.search({'session_id': session_id})
        except Exception:
            return None
        if usr_dt is None:
            return None
        sess_dt = self.user_id_by_session_id.get(session_id)
        if len(usr_dt) <= 0:
            return None
        if self.session_duration <= 0:
            usr_id = sess_dt.get("user_id")
            return usr_id
        cur_time = datetime.datetime.now()
        time_span = datetime.timedelta(seconds=self.session_duration)
        exp_time = sess_dt.get("created_at") + time_span
        if exp_time < cur_time:
            return None
        return sess_dt['user_id']

    def destroy_session(self, request=None) -> bool:
        """Destroys an authenticated session.
        """
        if request is None:
            return False
        sess_id = self.session_cookie(request)
        if sess_id is None:
            return False
        usr_id = self.user_id_for_session_id(sess_id)
        if usr_id is None:
            return False
        del self.user_id_by_session_id[sess_id]
        try:
            sess = UserSession.search({'session_id': sess_id})
        except Exception:
            return None
        if len(sess) <= 0:
            return False
        sess.remove()
        del self.user_id_by_session_id["sess_id"]
        return True
