# EasyAuth Flask SDK — Connector Documentation

The decorators in `easyauth_flask.py` ( covered in README.md ) cover most use cases. But if you need full manual control over how tokens are resolved, when data is fetched, or how errors are handled — the `LoginConnector` class is what powers everything under the hood, and it's available to use directly.

🌐 [easy-auth.dev](https://easy-auth.dev) &nbsp;|&nbsp; 📦 [AvikYadav/EasyAuth](https://github.com/AvikYadav/EasyAuth)

---

## Overview

`LoginConnector` is the base HTTP client that talks to the EasyAuth server. It handles token decryption, endpoint resolution, and all three core API calls — retrieve, update, and verify.

Every decorator in `easyauth_flask.py` uses a single shared instance of this class internally. When you import `connector` directly, you're getting that same instance.

```python
from easyauth_flask import connector
```

Or instantiate your own:

```python
from _connector import LoginConnector

connector = LoginConnector(
    username="your_username",
    service_name="your_service_name",
    api_key="your_api_key",
    base_url="https://easy-auth.dev",
)
```

---

## Constructor

```python
LoginConnector(
    username: str,
    service_name: str,
    api_key: str,
    base_url: str = "https://easy-auth.dev"
)
```

### Parameters

**`username`** *(str, required)*
Your EasyAuth platform username. This identifies which user namespace to query — it's the same username you log into the dashboard with.

**`service_name`** *(str, required)*
The name of the registered service. Must match exactly what you created on the dashboard. This scopes all user data to that specific service.

**`api_key`** *(str, required)*
The Fernet encryption key generated when you created the service. Shown once on the dashboard — if lost, the service must be deleted and recreated. This key is used to decrypt every incoming token before sending it to the server.

**`base_url`** *(str, optional)*
The root URL of the EasyAuth server. Defaults to `https://easy-auth.dev`. Override this for local development:
```python
base_url = "http://127.0.0.1:5000"
```

---

## Attributes

Once instantiated, the connector exposes the following attributes:

| Attribute | Value | Description |
|---|---|---|
| `self.base_url` | `"https://easy-auth.dev"` | Base URL, trailing slash stripped |
| `self.username` | `"your_username"` | Platform username |
| `self.service_name` | `"your_service_name"` | Registered service name |
| `self.api_key` | `"your_api_key"` | Fernet key for token decryption |
| `self.endpoint_retrieve` | `/retrieve/<username>/<service>` | Full URL for fetching user data |
| `self.endpoint_update` | `/update/<username>/<service>` | Full URL for writing user data |
| `self.endpoint_verify` | `/verify/<username>/<service>` | Full URL for token verification |

These are built once in `__init__` and reused on every call — no string formatting on every request.

---

## Methods

---

### `get_user_data(token)`

Fetches the stored data for the user identified by the token.

```python
result = connector.get_user_data(token)
```

**What it does internally:**
1. Decrypts the token using `self.api_key`
2. POSTs `{"token": <decrypted>}` to `/retrieve/<username>/<service>`
3. Returns the parsed JSON response

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `token` | `str` | The encrypted token received from EasyAuth callback URL |

**Returns:**

```python
# On success
{
    "username": "john_doe",
    "data": {
        "plan": "pro",
        "onboarded": True,
        # ... whatever you've stored
    }
}

# On failure
None
```

**Example:**

```python
result = connector.get_user_data(token)

if result is None:
    return jsonify({"error": "Invalid token"}), 401

username  = result["username"]
user_data = result["data"]
```

---

### `send_or_update_user_data(token, data)`

Writes or overwrites the user's stored data on EasyAuth. The entire `user_data` field is replaced with whatever you pass in.

```python
result = connector.send_or_update_user_data(token, {"plan": "pro", "onboarded": True})
```

**What it does internally:**
1. Decrypts the token using `self.api_key`
2. POSTs `{"token": <decrypted>, "user_data": data}` to `/update/<username>/<service>`
3. Returns the parsed JSON response

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `token` | `str` | The encrypted token received from EasyAuth |
| `data` | `dict` | Any JSON-serializable dict to store against this user |

**Returns:**

```python
# On success
{"status": "SUCCESS"}

# On failure
None
```

**Example:**

```python
connector.send_or_update_user_data(token, {
    "plan":         "pro",
    "onboarded":    True,
    "last_login":   "2026-03-07",
    "preferences":  {"theme": "dark", "language": "en"},
})
```

> **Note:** This is a full overwrite, not a merge. If you want to preserve existing fields, fetch the data first with `get_user_data()`, update the dict in Python, then write it back.

```python
result    = connector.get_user_data(token)
data      = result["data"] or {}
data["plan"] = "pro"                       # update one field
connector.send_or_update_user_data(token, data)   # write back
```

---

### `verify_user_login(token)`

Checks whether a token is valid for this service — without fetching any user data. Faster than `get_user_data` when you only need a yes/no answer.

```python
result = connector.verify_user_login(token)
```

**What it does internally:**
1. Decrypts the token using `self.api_key`
2. POSTs `{"token": <decrypted>}` to `/verify/<username>/<service>`
3. Returns the parsed JSON response

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `token` | `str` | The encrypted token received from EasyAuth |

**Returns:**

```python
# On success
{"status": "SUCCESS"}

# On failure (expired, invalid, or user not in service)
None
```

**Example:**

```python
if connector.verify_user_login(token) is None:
    return jsonify({"error": "Unauthorised"}), 401

# carry on
```

---

### `decrypt_token(token)`

Decrypts the Fernet-encrypted token using `self.api_key`. Called internally by every method before sending the token to the server — but exposed publicly if you need the raw JWT for any reason.

```python
raw_jwt = connector.decrypt_token(token)
```

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `token` | `str` | The encrypted token string from EasyAuth |

**Returns:** The decrypted JWT string.

> Tokens arriving from the EasyAuth callback URL are Fernet-encrypted. The server only accepts decrypted JWTs. You never need to call this manually unless you're doing something custom with the raw JWT.

---

## Using the Connector Directly — Full Manual Example

```python
from flask import Flask, request, jsonify
from _connector import LoginConnector

app = Flask(__name__)

connector = LoginConnector(
    username="your_username",
    service_name="your_service_name",
    api_key="your_api_key",
)


@app.route("/callback")
def callback():
    # Token arrives from EasyAuth after user logs in
    token = request.args.get("token")
    if not token:
        return jsonify({"error": "No token"}), 401

    # Verify first
    if connector.verify_user_login(token) is None:
        return jsonify({"error": "Invalid token"}), 401

    # Fetch full data
    result = connector.get_user_data(token)
    username = result["username"]
    user_data = result["data"] or {}

    # First time user — write initial data
    if not user_data.get("onboarded"):
        connector.send_or_update_user_data(token, {
            "onboarded": True,
            "plan": "free",
        })

    return jsonify({"welcome": username})
```

---

## When to Use the Connector vs the Decorators

| Use case | Recommended approach |
|---|---|
| Protect a route, token is enough | `@login_required` |
| Protect a route + need user data | `@fetch_user_data` |
| Write user data inside a route | `connector.send_or_update_user_data()` |
| Read + update data in same request | `connector.get_user_data()` then `connector.send_or_update_user_data()` |
| Custom token resolution logic | Instantiate `LoginConnector` directly |
| Non-Flask Python app | Instantiate `LoginConnector` directly — no Flask dependency |