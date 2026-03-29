import inspect
from functools import wraps
from flask import request, jsonify, redirect, make_response
from easyauth._config import get_connector


# ── Signature guard ───────────────────────────────────────────────────────────

def _assert_params(func, required: list[str], decorator_name: str):
    """
    Raises a clear TypeError at decoration time if `func` is missing any of
    the parameter names that the decorator will inject at request time.

    Args:
        func           : The route function being decorated.
        required       : Parameter names the decorator will inject.
        decorator_name : Name used in the error message.
    """
    actual  = inspect.signature(func).parameters
    missing = [p for p in required if p not in actual]
    if missing:
        missing_str = ", ".join(missing)
        params_str  = ", ".join(required)
        raise TypeError(
            f"\n\n  @{decorator_name} on '{func.__name__}' is missing required parameter(s): {missing_str}\n"
            f"  Fix: add them to your function signature.\n\n"
            f"  def {func.__name__}({params_str}):\n"
            f"      ..."
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


def _clear_cookie(response):
    """Removes the auth_token cookie by expiring it immediately."""
    response.delete_cookie(
        "auth_token",
        httponly=True,
        secure=True,
        samesite="Strict",
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
    _assert_params(f, ["token"], "login_required")

    @wraps(f)
    def decorated(*args, **kwargs):
        token, from_url = _resolve_token()

        if not token:
            return jsonify({"error": "No token provided."}), 401

        result = get_connector().verify_user_login(token)

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
        _assert_params(f, ["token"], "login_required_redirect")

        @wraps(f)
        def decorated(*args, **kwargs):
            token, from_url = _resolve_token()

            if not token:
                return redirect(redirect_url)

            result = get_connector().verify_user_login(token)

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
    _assert_params(f, ["token", "username", "user_data"], "fetch_user_data")

    @wraps(f)
    def decorated(*args, **kwargs):
        token, from_url = _resolve_token()

        if not token:
            return jsonify({"error": "No token provided."}), 401

        result = get_connector().get_user_data(token)

        if result is None:
            return jsonify({"error": "Invalid or expired token."}), 401

        username  = result.get("username")
        user_data = result.get("data") or {}

        response = make_response(f(*args, username=username, user_data=user_data, token=token, **kwargs))

        if from_url:
            _attach_cookie(response, token)

        return response

    return decorated


# ── 4. @logout ────────────────────────────────────────────────────────────────

def logout(f):
    """
    Clears the auth_token cookie from the response if one is present.
    The decorated route still executes normally — this decorator only handles
    the cookie side-effect, so you remain in full control of what the route
    returns (redirect, JSON confirmation, rendered page, etc.).

    If no cookie is present nothing breaks — the route still runs as normal.

    Usage:
        @app.route("/logout")
        @logout
        def logout_view():
            return redirect("/login")

        # Or with a JSON confirmation:
        @app.route("/logout")
        @logout
        def logout_view():
            return jsonify({"message": "Logged out successfully."})
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        response = make_response(f(*args, **kwargs))

        if request.cookies.get("auth_token"):
            _clear_cookie(response)

        return response

    return decorated


# ── Example usage ─────────────────────────────────────────────────────────────

# from flask import Flask, render_template
# from auth_decorator import login_required, login_required_redirect, fetch_user_data, logout
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
#
#
# # Clear the auth cookie and redirect to login
# @app.route("/logout")
# @logout
# def logout_view():
#     return redirect("/login")