import os
from ._connector import LoginConnector

# ── Internal state ────────────────────────────────────────────────────────────

_username:     str | None = None
_service_name: str | None = None
_api_key:      str | None = None
_base_url:     str        = "https://easy-auth.dev"

_connector: LoginConnector | None = None


# ── Public: called by easyauth.configure() ────────────────────────────────────

def configure(
    username:     str | None = None,
    service_name: str | None = None,
    api_key:      str | None = None,
    base_url:     str        = "https://easy-auth.dev",
) -> None:
    """
    Store credentials for lazy connector initialisation.
    Call this once at app startup before the first request.

    Any value not supplied here falls back to the corresponding
    EASYAUTH_* environment variable.
    """
    global _username, _service_name, _api_key, _base_url, _connector

    _username     = username     or os.getenv("EASYAUTH_USERNAME")
    _service_name = service_name or os.getenv("EASYAUTH_SERVICE_NAME")
    _api_key      = api_key      or os.getenv("EASYAUTH_API_KEY")
    _base_url     = base_url     or os.getenv("EASYAUTH_BASE_URL", "https://easy-auth.dev")

    _connector = None   # reset so it's rebuilt with new credentials


# ── Internal: called by every framework file ──────────────────────────────────

def get_connector() -> LoginConnector:
    """
    Returns the shared LoginConnector, building it lazily on first call.
    Raises a clear RuntimeError if configure() was never called and no
    environment variables are set.
    """
    global _connector

    if _connector is not None:
        return _connector

    # ── Env var fallback (in case configure() was never called explicitly)
    username     = _username     or os.getenv("EASYAUTH_USERNAME")
    service_name = _service_name or os.getenv("EASYAUTH_SERVICE_NAME")
    api_key      = _api_key      or os.getenv("EASYAUTH_API_KEY")
    base_url     = _base_url     or os.getenv("EASYAUTH_BASE_URL", "https://easy-auth.dev")

    missing = [
        name for name, val in [
            ("username",     username),
            ("service_name", service_name),
            ("api_key",      api_key),
        ]
        if not val
    ]

    if missing:
        missing_str = ", ".join(missing)
        raise RuntimeError(
            f"\n\n  easyauth is not configured — missing: {missing_str}\n\n"
            f"  Fix (option 1): call configure() at app startup:\n"
            f"      import easyauth\n"
            f"      easyauth.configure(username=..., service_name=..., api_key=...)\n\n"
            f"  Fix (option 2): set environment variables:\n"
            f"      EASYAUTH_USERNAME=...\n"
            f"      EASYAUTH_SERVICE_NAME=...\n"
            f"      EASYAUTH_API_KEY=...\n"
        )

    _connector = LoginConnector(
        username=username,
        service_name=service_name,
        api_key=api_key,
        base_url=base_url,
    )
    return _connector