"""
easyauth — Simple auth decorators for Flask, FastAPI, and Django.

Quickstart
----------
    import easyauth

    easyauth.configure(
        username     = "john_doe",
        service_name = "my_app",
        api_key      = "my_secret_key",
    )

    # Flask
    from easyauth.flask import login_required, fetch_user_data, logout

    # FastAPI
    from easyauth.fastapi import require_login, require_user_data

    # Django
    from easyauth.django import login_required, fetch_user_data

Env var fallback (no configure() call needed)
---------------------------------------------
    EASYAUTH_USERNAME=john_doe
    EASYAUTH_SERVICE_NAME=my_app
    EASYAUTH_API_KEY=my_secret_key
"""

from ._config    import configure          # noqa: F401  ← user calls this
from ._connector import LoginConnector     # noqa: F401  ← exposed for advanced use

__all__ = ["configure", "LoginConnector"]