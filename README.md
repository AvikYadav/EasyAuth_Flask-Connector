# ⚡ EasyAuth Flask SDK

**One line to protect a route. One line to get user data. That's the whole integration.**

🌐 [easy-auth.dev](https://easy-auth.dev) &nbsp;|&nbsp; 📦 [AvikYadav/EasyAuth](https://github.com/AvikYadav/EasyAuth)

---

## Quickstart

```bash
pip install -r requirements.txt
```

Drop `easyauth_flask.py`, `easyAuthBaseConnector.py`, and `encryption.py` into your project, fill in your credentials from your [EasyAuth dashboard](https://easy-auth.dev), and import:

```python
from easyauth_flask import login_required, login_required_redirect, fetch_user_data
```

**That's the entire setup.** Now protect any route in one line:

```python
@app.route("/dashboard")
@login_required
def dashboard(token):
    return "You're in."
```

---

You already have a Flask app. EasyAuth slots into it with almost zero code change — fill in your credentials once, drop a decorator on your routes, and auth is done.

```python
# Before EasyAuth
@app.route("/dashboard")
def dashboard():
    ...

# After EasyAuth — that's the entire change
@app.route("/dashboard")
@login_required
def dashboard(token):
    ...
```

No sessions. No middleware. No JWT libraries. No passport strategies. One decorator.

---

## Setup — fill in three fields, never think about it again

Open `easyauth_flask.py` and replace these three values with what's on your EasyAuth dashboard:

```python
connector = LoginConnector(
    username     = "your_username",      # ← your EasyAuth username
    service_name = "your_service_name",  # ← your registered service
    api_key      = "your_api_key",       # ← shown once on service creation
)
```

Then import at the top of your Flask app:

```python
from easyauth_flask import login_required, login_required_redirect, fetch_user_data
```

**That's the entire setup.** Every route in your app can now be auth-protected.

---

## 1 line to protect a route

```python
@app.route("/dashboard")
@login_required                          # ← this is the 1 line
def dashboard(token):
    return "You're in."
```

Unauthenticated users get a `401`. Authenticated users get through. The `token` is injected automatically — you don't fetch it, decode it, or verify it yourself.

---

## 1 line to get user data

```python
@app.route("/profile")
@fetch_user_data                         # ← this is the 1 line
def profile(username, user_data, token):
    return jsonify({"hello": username, "your_data": user_data})
```

`username`, `user_data`, and `token` all arrive as arguments. No API calls in your code. No token parsing. Just use them.

---

## Prefer a redirect over a 401?

```python
@app.route("/settings")
@login_required_redirect(redirect_url="/login")   # ← same idea, redirects instead
def settings(token):
    return render_template("settings.html")
```

---

## Tokens manage themselves

The first time a user hits your app, EasyAuth sends their token in the URL. After that, the SDK handles everything silently:

```
First visit   →  ?token=... arrives from EasyAuth  →  saved to cookie automatically
Every visit after  →  cookie is used  →  no token in URL needed
User logs out or token expires  →  401 / redirect
```

You never write a single line of cookie or session code.

---

## Write user data in one call

```python
from easyauth_flask import connector

connector.send_or_update_user_data(token, {
    "plan": "pro",
    "onboarded": True,
    "last_page": "/dashboard",
})
```

Anything JSON-serializable. It's stored against the user on EasyAuth's side and comes back in `user_data` on every `@fetch_user_data` request.

---

## A full app, for reference

```python
from flask import Flask, jsonify, render_template
from easyauth_flask import login_required, login_required_redirect, fetch_user_data, connector

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")   # public, no auth


@app.route("/dashboard")
@login_required_redirect(redirect_url="/login")
def dashboard(token):
    return render_template("dashboard.html")


@app.route("/profile")
@fetch_user_data
def profile(username, user_data, token):
    return jsonify({"username": username, "data": user_data})


@app.route("/save-preferences")
@login_required
def save_preferences(token):
    connector.send_or_update_user_data(token, {"theme": "dark"})
    return jsonify({"status": "saved"})


if __name__ == "__main__":
    app.run(debug=True)
```

Three decorators, one connector call. That's the entire auth layer of this app.

---

## Three decorators, one table

| Decorator | What it does | Injects |
|---|---|---|
| `@login_required` | Blocks unauthenticated requests → `401` | `token` |
| `@login_required_redirect` | Blocks unauthenticated requests → redirect | `token` |
| `@fetch_user_data` | Blocks + fetches user data in one shot | `username, user_data, token` |

---

*EasyAuth Flask SDK — auth that gets out of your way.*
