import inspect
from functools import wraps
from django.http import JsonResponse
from django.shortcuts import redirect
from easyauth._config import get_connector





# ── Signature guard ───────────────────────────────────────────────────────────

def _assert_params(func, required: list[str], decorator_name: str):
    """
    Raises a clear TypeError at decoration time if `func` is missing any of
    the parameter names that the decorator will inject at request time.

    Django views always take `request` as their first positional arg, which is
    NOT in `required` — only the extra injected kwargs need to be checked.

    Args:
        func           : The view function being decorated.
        required       : Parameter names the decorator will inject.
        decorator_name : Name used in the error message.
    """
    actual  = inspect.signature(func).parameters
    missing = [p for p in required if p not in actual]
    if missing:
        missing_str = ", ".join(missing)
        params_str  = ", ".join(["request"] + required)
        raise TypeError(
            f"\n\n  @{decorator_name} on '{func.__name__}' is missing required parameter(s): {missing_str}\n"
            f"  Fix: add them to your function signature.\n\n"
            f"  def {func.__name__}({params_str}):\n"
            f"      ..."
        )


# ── Shared helpers ────────────────────────────────────────────────────────────

def _resolve_token(request):
    """
    Resolves the token from URL query params or cookie.
    Returns (token, from_url) — from_url=True means we need to save it to cookie.
    Returns (None, False) if no token found anywhere.

    Note: request.GET reads the query string on ALL HTTP methods (GET, POST etc.)
    so ?token=... in the URL always works regardless of request method.
    """
    token = request.GET.get("token")
    if token:
        return token, True          # found in URL — should be saved to cookie

    token = request.COOKIES.get("auth_token")
    if token:
        return token, False         # found in cookie — already saved, no action needed

    return None, False              # not found anywhere


def _attach_cookie(response, token):
    """Saves the token to an httponly cookie on the response."""
    response.set_cookie(
        "auth_token",
        token,
        httponly = True,
        secure   = True,
        samesite = "Strict",
        max_age  = 3600,
        path     = "/",
    )
    return response


def _clear_cookie(response):
    """Removes the auth_token cookie by expiring it immediately."""
    response.delete_cookie(
        "auth_token",
        samesite = "Strict",
        path     = "/",
    )
    return response


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION-BASED VIEW DECORATORS
# ══════════════════════════════════════════════════════════════════════════════

# ── 1. @login_required ────────────────────────────────────────────────────────
# ⚠️  NAME CONFLICT WARNING: Django ships its own login_required in
# django.contrib.auth.decorators. Always use explicit imports to avoid
# accidentally shadowing one with the other.
#
# Safe:   from easyauth_django import login_required as easyauth_login_required
# Risky:  from easyauth_django import *

def login_required(view_func):
    """
    Decorator for function-based views.
    Blocks access if no valid token is present.
    Checks URL first, then falls back to cookie.
    If token found in URL, saves it to cookie automatically.
    Injects token as a keyword argument into the view.

    Returns 401 JSON on failure.

    Usage:
        @login_required
        def dashboard(request, token):
            return JsonResponse({"token": token})
    """
    _assert_params(view_func, ["token"], "login_required")

    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        token, from_url = _resolve_token(request)

        if not token:
            return JsonResponse({"error": "No token provided."}, status=401)

        result = get_connector().verify_user_login(token)

        if result is None:
            return JsonResponse({"error": "Invalid or expired token."}, status=401)

        # BUG FIX: pop 'token' from URL kwargs if present to avoid
        # TypeError: got multiple values for keyword argument 'token'
        kwargs.pop("token", None)

        response = view_func(request, *args, token=token, **kwargs)

        if from_url:
            _attach_cookie(response, token)

        return response

    return wrapped


# ── 2. @login_required_redirect ───────────────────────────────────────────────

def login_required_redirect(redirect_url="/login"):
    """
    Same as @login_required but redirects to a page on failure instead of 401.
    Wrap with the redirect URL to create the decorator.
    Injects token as a keyword argument into the view.

    Usage:
        @login_required_redirect(redirect_url="/login")
        def dashboard(request, token):
            return render(request, "dashboard.html")
    """
    def decorator(view_func):
        _assert_params(view_func, ["token"], "login_required_redirect")

        @wraps(view_func)
        def wrapped(request, *args, **kwargs):
            token, from_url = _resolve_token(request)

            if not token:
                return redirect(redirect_url)

            result = get_connector().verify_user_login(token)

            if result is None:
                return redirect(redirect_url)

            # BUG FIX: pop 'token' from URL kwargs if present to avoid
            # TypeError: got multiple values for keyword argument 'token'
            kwargs.pop("token", None)

            response = view_func(request, *args, token=token, **kwargs)

            if from_url:
                _attach_cookie(response, token)

            return response

        return wrapped
    return decorator


# ── 3. @fetch_user_data ───────────────────────────────────────────────────────

def fetch_user_data(view_func):
    """
    Decorator for function-based views.
    Verifies the token AND fetches the user's stored data from EasyAuth.
    Checks URL first, then falls back to cookie.
    If token found in URL, saves it to cookie automatically.
    Injects username, user_data, and token into the view.

    Returns 401 JSON on failure.

    Usage:
        @fetch_user_data
        def profile(request, username, user_data, token):
            return JsonResponse({"username": username, "data": user_data})
    """
    _assert_params(view_func, ["token", "username", "user_data"], "fetch_user_data")

    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        token, from_url = _resolve_token(request)

        if not token:
            return JsonResponse({"error": "No token provided."}, status=401)

        result = get_connector().get_user_data(token)

        if result is None:
            return JsonResponse({"error": "Invalid or expired token."}, status=401)

        username  = result.get("username")
        user_data = result.get("data") or {}

        # BUG FIX: if the URL pattern contains <str:username> or <str:token>,
        # Django passes them in kwargs. Passing username/token again as kwargs
        # would raise TypeError: got multiple values for keyword argument.
        # Pop any conflicting keys before forwarding kwargs to the view.
        kwargs.pop("username",  None)
        kwargs.pop("user_data", None)
        kwargs.pop("token",     None)

        response = view_func(
            request, *args,
            username  = username,
            user_data = user_data,
            token     = token,
            **kwargs
        )

        if from_url:
            _attach_cookie(response, token)

        return response

    return wrapped


# ── 4. @logout ────────────────────────────────────────────────────────────────

def logout(view_func):
    """
    Decorator for function-based views.
    Clears the auth_token cookie from the response if one is present.
    The decorated view still executes normally — this decorator only handles
    the cookie side-effect, so you remain in full control of what the view
    returns (redirect, JSON confirmation, rendered page, etc.).

    If no cookie is present nothing breaks — the view still runs as normal.

    Usage:
        @logout
        def logout_view(request):
            return redirect("/login")

        # Or with a JSON confirmation:
        @logout
        def logout_view(request):
            return JsonResponse({"message": "Logged out successfully."})
    """
    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        response = view_func(request, *args, **kwargs)

        if request.COOKIES.get("auth_token"):
            _clear_cookie(response)

        return response

    return wrapped


# ══════════════════════════════════════════════════════════════════════════════
# CLASS-BASED VIEW MIXINS
# ══════════════════════════════════════════════════════════════════════════════

# ── 5. LoginRequiredMixin ─────────────────────────────────────────────────────

class LoginRequiredMixin:
    """
    Mixin for class-based views.
    Blocks access if no valid token is present.
    Checks URL first, then falls back to cookie.
    If token found in URL, saves it to cookie automatically.
    Attaches token to self.token for use inside the view.

    Returns 401 JSON on failure.

    Usage:
        class DashboardView(LoginRequiredMixin, View):
            def get(self, request):
                return JsonResponse({"token": self.token})
    """
    def dispatch(self, request, *args, **kwargs):
        token, from_url = _resolve_token(request)

        if not token:
            return JsonResponse({"error": "No token provided."}, status=401)

        result = get_connector().verify_user_login(token)

        if result is None:
            return JsonResponse({"error": "Invalid or expired token."}, status=401)

        self.token    = token
        self.from_url = from_url

        response = super().dispatch(request, *args, **kwargs)

        if from_url:
            _attach_cookie(response, token)

        return response


# ── 6. LoginRequiredRedirectMixin ─────────────────────────────────────────────

class LoginRequiredRedirectMixin:
    """
    Mixin for class-based views.
    Same as LoginRequiredMixin but redirects on failure instead of returning 401.
    Set login_url as a class attribute to control where the user is redirected.
    Attaches token to self.token for use inside the view.

    Usage:
        class DashboardView(LoginRequiredRedirectMixin, View):
            login_url = "/login"    # default

            def get(self, request):
                return render(request, "dashboard.html")
    """
    login_url = "/login"

    def dispatch(self, request, *args, **kwargs):
        token, from_url = _resolve_token(request)

        if not token:
            return redirect(self.login_url)

        result = get_connector().verify_user_login(token)

        if result is None:
            return redirect(self.login_url)

        self.token    = token
        self.from_url = from_url

        response = super().dispatch(request, *args, **kwargs)

        if from_url:
            _attach_cookie(response, token)

        return response


# ── 7. FetchUserDataMixin ─────────────────────────────────────────────────────

class FetchUserDataMixin:
    """
    Mixin for class-based views.
    Verifies the token AND fetches the user's stored data from EasyAuth.
    Checks URL first, then falls back to cookie.
    If token found in URL, saves it to cookie automatically.
    Attaches username, user_data, and token to self for use inside the view.

    Returns 401 JSON on failure.

    Usage:
        class ProfileView(FetchUserDataMixin, View):
            def get(self, request):
                return JsonResponse({
                    "username": self.username,
                    "data":     self.user_data,
                })
    """
    def dispatch(self, request, *args, **kwargs):
        token, from_url = _resolve_token(request)

        if not token:
            return JsonResponse({"error": "No token provided."}, status=401)

        result = get_connector().get_user_data(token)

        if result is None:
            return JsonResponse({"error": "Invalid or expired token."}, status=401)

        self.token     = token
        self.username  = result.get("username")
        self.user_data = result.get("data") or {}
        self.from_url  = from_url

        response = super().dispatch(request, *args, **kwargs)

        if from_url:
            _attach_cookie(response, token)

        return response


# ── 8. LogoutMixin ────────────────────────────────────────────────────────────

class LogoutMixin:
    """
    Mixin for class-based views.
    Clears the auth_token cookie from the response if one is present.
    The view still executes normally — this mixin only handles the cookie
    side-effect, so you remain in full control of what the view returns.

    If no cookie is present nothing breaks — the view still runs as normal.

    Usage:
        class LogoutView(LogoutMixin, View):
            def get(self, request):
                return redirect("/login")
    """
    def dispatch(self, request, *args, **kwargs):
        response = super().dispatch(request, *args, **kwargs)

        if request.COOKIES.get("auth_token"):
            _clear_cookie(response)

        return response


# ── Example usage ─────────────────────────────────────────────────────────────

# ── Function-based views ──────────────────────────────────────────────────────
#
# from django.http import JsonResponse
# from django.shortcuts import render
# from easyauth_django import login_required, login_required_redirect, fetch_user_data, logout, connector
#
#
# # Just gate the route — 401 on failure
# @login_required
# def home(request, token):
#     return JsonResponse({"token": token})
#
#
# # Gate + redirect on failure
# @login_required_redirect(redirect_url="/login")
# def dashboard(request, token):
#     return render(request, "dashboard.html")
#
#
# # Gate + full user data
# @fetch_user_data
# def profile(request, username, user_data, token):
#     return JsonResponse({"username": username, "data": user_data})
#
#
# # Clear the auth cookie and redirect to login
# @logout
# def logout_view(request):
#     return redirect("/login")
#
#
# # Write user data inside a view
# @login_required
# def onboard(request, token):
#     connector.send_or_update_user_data(token, {"onboarded": True, "plan": "free"})
#     return JsonResponse({"status": "saved"})
#
#
# ── Class-based views ─────────────────────────────────────────────────────────
#
# from django.views import View
# from easyauth_django import (
#     LoginRequiredMixin, LoginRequiredRedirectMixin,
#     FetchUserDataMixin, LogoutMixin,
# )
#
#
# # Just gate — 401 on failure
# class HomeView(LoginRequiredMixin, View):
#     def get(self, request):
#         return JsonResponse({"token": self.token})
#
#
# # Gate + redirect on failure
# class DashboardView(LoginRequiredRedirectMixin, View):
#     login_url = "/login"
#
#     def get(self, request):
#         return render(request, "dashboard.html")
#
#
# # Gate + full user data
# class ProfileView(FetchUserDataMixin, View):
#     def get(self, request):
#         return JsonResponse({
#             "username": self.username,
#             "data":     self.user_data,
#         })
#
#
# # Clear the auth cookie
# class LogoutView(LogoutMixin, View):
#     def get(self, request):
#         return redirect("/login")