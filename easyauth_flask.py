from functools import wraps
from flask import request, jsonify, redirect, make_response
from easyAuthBaseConnector import LoginConnector


# ── Initialise your connector once ────────────────────────────────────────────

connector = LoginConnector(
    username     = "your_username",
    service_name = "your_service_name",
    api_key      = "your_api_key",
    base_url     = "https://easy-auth.dev",
)


# ── Shared helper ─────────────────────────────────────────────────────────────

def _resolve_token():
    """
    Resolves the token from URL params or cookie.
    Returns (token, from_url) — from_url=True means we need to save it to cookie.
    Returns (None, False) if no token found anywhere.
    """
    token = request.args.get("token")
    if token:
        return token, True          # found in URL — should be saved to cookie

    token = request.cookies.get("auth_token")
    if token:
        return token, False         # found in cookie — already saved, no action needed

    return None, False              # not found anywhere


def _attach_cookie(response, token):
    """Saves the token to an httponly cookie on the response."""
    response.set_cookie(
        "auth_token",
        token,
        httponly=True,
        secure=True,
        samesite="Strict",
        max_age=3600,
        path="/",
    )
    return response


# ── 1. @login_required ────────────────────────────────────────────────────────

def login_required(f):
    """
    Blocks access to the route if no valid token is present.
    Checks URL first, then falls back to cookie.
    If token is found in URL and not yet in cookie, saves it to cookie.
    Injects only the token into the route.

    Returns 401 JSON on failure.

    Usage:
        @app.route("/dashboard")
        @login_required
        def dashboard(token):
            return jsonify({"token": token})
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token, from_url = _resolve_token()

        if not token:
            return jsonify({"error": "No token provided."}), 401

        result = connector.verify_user_login(token)

        if result is None:
            return jsonify({"error": "Invalid or expired token."}), 401

        response = make_response(f(*args, token=token, **kwargs))

        if from_url:
            _attach_cookie(response, token)

        return response

    return decorated


# ── 2. @login_required_redirect ───────────────────────────────────────────────

def login_required_redirect(redirect_url="/login"):
    """
    Same as @login_required but redirects on failure instead of returning 401.
    Checks URL first, then falls back to cookie.
    If token is found in URL and not yet in cookie, saves it to cookie.
    Injects only the token into the route.

    Usage:
        @app.route("/dashboard")
        @login_required_redirect(redirect_url="/login")
        def dashboard(token):
            return render_template("dashboard.html", token=token)
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token, from_url = _resolve_token()

            if not token:
                return redirect(redirect_url)

            result = connector.verify_user_login(token)

            if result is None:
                return redirect(redirect_url)

            response = make_response(f(*args, token=token, **kwargs))

            if from_url:
                _attach_cookie(response, token)

            return response

        return decorated
    return decorator


# ── 3. @fetch_user_data ───────────────────────────────────────────────────────

def fetch_user_data(f):
    """
    Verifies the token AND fetches the user's stored data from EasyAuth.
    Checks URL first, then falls back to cookie.
    If token is found in URL and not yet in cookie, saves it to cookie.
    Injects username, user_data, and token into the route.

    Returns 401 JSON on failure.

    Usage:
        @app.route("/profile")
        @fetch_user_data
        def profile(username, user_data, token):
            return jsonify({"username": username, "data": user_data})
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token, from_url = _resolve_token()

        if not token:
            return jsonify({"error": "No token provided."}), 401

        result = connector.get_user_data(token)

        if result is None:
            return jsonify({"error": "Invalid or expired token."}), 401

        username  = result.get("username")
        user_data = result.get("data") or {}

        response = make_response(f(*args, username=username, user_data=user_data, token=token, **kwargs))

        if from_url:
            _attach_cookie(response, token)

        return response

    return decorated


# ── Example usage ─────────────────────────────────────────────────────────────

# from flask import Flask, render_template
# from auth_decorator import login_required, login_required_redirect, fetch_user_data
#
# app = Flask(__name__)
#
#
# # Just gate the route — token saved to cookie on first visit
# @app.route("/home")
# @login_required
# def home(token):
#     return jsonify({"token": token})
#
#
# # Gate + redirect on failure — token saved to cookie on first visit
# @app.route("/settings")
# @login_required_redirect(redirect_url="/login")
# def settings(token):
#     return render_template("settings.html", token=token)
#
#
# # Gate + full user data — token saved to cookie on first visit
# @app.route("/profile")
# @fetch_user_data
# def profile(username, user_data, token):
#     return jsonify({"username": username, "data": user_data})

