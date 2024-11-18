#!/usr/bin/env python3
""" Module of Users views
"""
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User
import os


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def auth_session_login() -> str:
    """ POST /api/v1/auth_session/login
    Login for user using email and password
    """
    email = request.form.get("email")
    pwd = request.form.get("password")
    if email is None or len(email) == 0:
        return jsonify({'error': "email missing"}), 400
    if pwd is None or len(pwd) == 0:
        return jsonify({'error': "password missing"}), 400
    try:
        userrs = User.search({'email': email})
    except Exception:
        return jsonify({"error": "no user found for this email"}), 404
    if len(userrs) == 0:
        return jsonify({"error": "no user found for this email"}), 404
    for usr in userrs:
        if usr.is_valid_password(pwd):
            from api.v1.app import auth
            sess = auth.create_session(getattr(usr, "id"))
            res = jsonify(usr.to_json())
            res.set_cookie(os.getenv("SESSION_NAME"), sess)
            return res
    return jsonify({"error": "wrong password"}), 401


@app_views.route('/auth_session/logout', methods=[
    'DELETE'], strict_slashes=False)
def auth_session_logout() -> str:
    """ DELETE /api/v1/auth_session/logout
    Logout for user
    """
    from api.v1.app import auth
    val = auth.destroy_session(request)
    if val is False:
        abort(404)
    else:
        return jsonify({}), 200
