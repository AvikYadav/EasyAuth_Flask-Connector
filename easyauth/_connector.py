import requests

from easyauth import _encryption


class LoginConnector:
    """
    Client connector for interacting with the auth service.

    Usage:
        connector = LoginConnector(
            base_url     = "http://127.0.0.1:5000",
            username     = "john_doe",
            service_name = "my_app",
            api_key      = "<your_api_key>",
        )

        # Send / update user data on the server
        connector.send_or_update_user_data(token="<jwt>", data={"theme": "dark"})

        # Retrieve user data from the server
        result = connector.get_user_data(token="<jwt>")
        # result keys: "username", "data"  (normalised from the API's "user_data")

        # Verify a login token
        result = connector.verify_user_login(token="<jwt>")
        # result keys: "message", "username"
    """

    def __init__(
        self,
        username: str,
        service_name: str,
        api_key: str,
        base_url: str = "https://easy-auth.dev",
    ):
        """
        Initialise the connector.

        Args:
            username     : The developer's username (collection owner).
            service_name : The registered service name.
            api_key      : Fernet key used to decrypt tokens before sending.
            base_url     : Base URL of the auth server.
        """
        self.base_url     = base_url.rstrip("/")
        self.username     = username
        self.service_name = service_name
        self.api_key      = api_key

        self.endpoint_retrieve = f"{self.base_url}/retrieve/{self.username}/{self.service_name}"
        self.endpoint_update   = f"{self.base_url}/update/{self.username}/{self.service_name}"
        self.endpoint_verify   = f"{self.base_url}/verify/{self.username}/{self.service_name}"

    # ── Public methods ────────────────────────────────────────────────────────

    def get_user_data(self, token: str) -> dict | None:
        """
        Retrieve user data from the server for the given JWT token.

        The API now returns::

            {"username": "<str>", "user_data": <dict>}

        This method normalises the response to::

            {"username": "<str>", "data": <dict>}

        so that easyflask.py (which reads ``result.get("data")``) continues
        to work without modification.

        Args:
            token : Encrypted JWT token of the authenticated user.

        Returns:
            Normalised dict on success, None on failure.
        """
        payload = {"token": self._decrypt_token(token)}

        try:
            response = requests.post(self.endpoint_retrieve, json=payload)

            if response.status_code == 200:
                result = response.json()
                # ── Normalise key: API returns "user_data", Flask layer reads "data"
                if "user_data" in result and "data" not in result:
                    result["data"] = result.pop("user_data")
                return result

            self._handle_error("get_user_data", response)
            return None

        except Exception as e:
            print(f"[LoginConnector] get_user_data — EXCEPTION: {e}")
            return None

    def send_or_update_user_data(self, token: str, data: dict) -> dict | None:
        """
        Store / overwrite arbitrary JSON data against the authenticated user.

        The API endpoint is ``POST /update/<user>/<service>`` and expects::

            {"token": "<jwt>", "user_data": <dict>}

        Returns:
            ``{"message": "User data updated."}`` on success, None on failure.

        Args:
            token : Encrypted JWT token of the authenticated user.
            data  : Any JSON-serialisable dict to store.
        """
        payload = {
            "token":     self._decrypt_token(token),
            "user_data": data,
        }

        try:
            response = requests.post(self.endpoint_update, json=payload)

            if response.status_code == 200:
                return response.json()

            self._handle_error("send_or_update_user_data", response)
            return None

        except Exception as e:
            print(f"[LoginConnector] send_or_update_user_data — EXCEPTION: {e}")
            return None

    def verify_user_login(self, token: str) -> dict | None:
        """
        Verify that a token is valid for this service.

        The API endpoint is ``POST /verify/<user>/<service>`` and returns::

            {"message": "Token is valid.", "username": "<str>"}

        easyflask.py only checks ``if result is None``, so the richer
        response shape is fully backwards-compatible.

        Args:
            token : Encrypted JWT token of the authenticated user.

        Returns:
            Dict with ``message`` and ``username`` on success, None on failure.
        """
        payload = {"token": self._decrypt_token(token)}

        try:
            response = requests.post(self.endpoint_verify, json=payload)

            if response.status_code == 200:
                return response.json()

            self._handle_error("verify_user_login", response)
            return None

        except Exception as e:
            print(f"[LoginConnector] verify_user_login — EXCEPTION: {e}")
            return None

    # ── Private helpers ───────────────────────────────────────────────────────

    def _decrypt_token(self, token: str) -> str:
        """Decrypt a Fernet-encrypted token before sending it to the API."""
        return _encryption.decrypt_message(token, self.api_key)

    def _handle_error(self, method: str, response: requests.Response) -> None:
        """
        Parse and log a structured error from a non-200 API response.

        The API always returns JSON in the form ``{"error": "<message>"}`` for
        failures.  Status codes map to these situations:

        +---------+------------------------------------------------------+
        | Code    | Meaning                                              |
        +=========+======================================================+
        | 401     | No token supplied, or token expired / invalid        |
        +---------+------------------------------------------------------+
        | 404     | Service name not registered, or user not in service  |
        +---------+------------------------------------------------------+
        | other   | Unexpected server-side error                         |
        +---------+------------------------------------------------------+

        Args:
            method   : Caller name for log context (e.g. "get_user_data").
            response : The raw ``requests.Response`` object.
        """
        code = response.status_code

        # Prefer the structured "error" field; fall back to raw text
        try:
            error_msg = response.json().get("error") or response.text
        except Exception:
            error_msg = response.text

        if code == 401:
            label = "AUTH FAILURE"
        elif code == 404:
            label = "NOT FOUND"
        else:
            label = "UNEXPECTED ERROR"

        print(f"[LoginConnector] {method} — {label} ({code}): {error_msg}")


# ── Example usage ─────────────────────────────────────────────────────────────
#
# if __name__ == "__main__":
#     api   = "Example-api"
#     TOKEN = "Example-encrypted-token"
#
#     connector = LoginConnector(
#         username     = "example_user",
#         service_name = "example_service",
#         api_key      = api,
#     )
#
#     # Store some user data
#     send_result = connector.send_or_update_user_data(TOKEN, {"msg": "hello from backend"})
#     print("Send result:", send_result)
#
#     # Retrieve user data (returns {"username": ..., "data": ...})
#     user_data = connector.get_user_data(TOKEN)
#     print("User data:", user_data)
#
#     # Verify login (returns {"message": ..., "username": ...})
#     login_verify = connector.verify_user_login(TOKEN)
#     print("Verification:", login_verify)