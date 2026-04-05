# Easy-Auth 
auth made so easyyyy

**Full authentication in under a minute. One decorator per route. Nothing else.**

Most auth setups take hours — JWT libraries, cookie logic, session management, login pages, token verification on every route. `easyauth` replaces all of it with a single pip install and three lines of configuration.

```bash
pip install easy-auth-sdk
```

---

## The entire setup — 60 seconds, no kidding

```python
# Step 1 — install (15 seconds)
# pip install easy-auth-sdk

# Step 2 — configure (5 seconds)
import easyauth
easyauth.configure(username="john_doe", service_name="my_app", api_key="your_key")

# Step 3 — protect a route (5 seconds)
from easyauth.easyflask import login_required_redirect

@app.route("/dashboard")
@login_required_redirect(redirect_url="https://easy-auth.dev/login/john_doe/my_app")
def dashboard(token):
    return render_template("dashboard.html")

# Done. Your app now has:
# ✅ Login page (hosted — no HTML to write)
# ✅ Token verification on every request
# ✅ Encrypted httponly cookies
# ✅ Auto logout on expiry
```

That's it. You didn't write a login page, a JWT decoder, a session handler, or a single line of cookie logic.

---

## Before & After

### Before — doing auth yourself

```python
# Every. Single. Route.
@app.route("/dashboard")
def dashboard():
    token = request.args.get("token") or request.cookies.get("auth_token")
    if not token:
        return redirect("/login")

    try:
        decrypted = fernet.decrypt(token.encode()).decode()
        payload   = jwt.decode(decrypted, SECRET_KEY, algorithms=["HS256"])
        username  = payload.get("sub")
    except Exception:
        return redirect("/login")

    response = make_response(render_template("dashboard.html", username=username))
    response.set_cookie("auth_token", token, httponly=True, secure=True, samesite="Strict")
    return response
```

15 lines of fragile boilerplate. Repeated on every protected route. One mistake and you have a security hole.

### After — with easyauth

```python
@app.route("/dashboard")
@login_required_redirect(redirect_url=LOGIN_URL)
def dashboard(token):
    return render_template("dashboard.html")
```

**Same security. 3 lines. Once.**

---

## You also don't need to build a login page

[easy-auth.dev](https://easy-auth.dev) hosts your login UI. Just point your users there — they log in, and get redirected back to your app with an encrypted token. `easyauth` picks it up automatically.

```
User visits /dashboard (not logged in)
       │
       ▼
Redirected → easy-auth.dev/login/john_doe/my_app   ← hosted for you
       │
       ▼  user logs in
Redirected → your-app.com/dashboard?token=<encrypted>
       │
       ▼  @login_required_redirect handles everything from here
Dashboard loads ✅  token saved to secure cookie ✅
```

**Your login URL is always:**
```
https://easy-auth.dev/login/your_username/your_service_name
```

No login page HTML. No form handling. No password storage. Nothing.

### Make it look like yours — custom login templates

Your users never need to feel like they left your app. easy-auth.dev lets you fully brand the login page:

1. Go to **easy-auth.dev → Services → your service → Login Page**
2. Upload your logo, set your brand colour, customise the heading and button text
3. That's it — the same URL now shows your branded UI

---

## Quickstart — the full picture

### 1. Create a service on easy-auth.dev

Sign up at [easy-auth.dev](https://easy-auth.dev), create a service, and grab your `username`, `service_name`, and `api_key`. Takes under a minute.

### 2. Install

```bash
pip install easy-auth-sdk
```

### 3. Configure — once, at app startup

```python
import easyauth

easyauth.configure(
    username     = "john_doe",
    service_name = "my_app",
    api_key      = "your_api_key",
)
```

Prefer environment variables? Don't write a single line of config code:

```bash
EASYAUTH_USERNAME=john_doe
EASYAUTH_SERVICE_NAME=my_app
EASYAUTH_API_KEY=your_api_key
```

Same behaviour. Works in any environment — local, staging, production — with no code changes.

### 4. Protect routes

```python
from easyauth.easyflask import login_required, login_required_redirect, fetch_user_data, logout
```

One import. All four decorators. Done.

---

## Decorators

### `@login_required`
For API routes. Returns `401 JSON` if the token is missing or invalid. Injects `token`.

```python
@app.route("/api/data")
@login_required
def api_data(token):
    return jsonify({"status": "ok"})
```

### `@login_required_redirect`
For HTML pages. Redirects to your login URL on failure instead of returning 401.

```python
@app.route("/dashboard")
@login_required_redirect(redirect_url="https://easy-auth.dev/login/john_doe/my_app")
def dashboard(token):
    return render_template("dashboard.html")
```

### `@fetch_user_data`
Verifies the token **and** loads the user's stored data in one shot. Injects `username`, `user_data`, and `token`.

```python
@app.route("/profile")
@fetch_user_data
def profile(username, user_data, token):
    return render_template("profile.html",
        username = username,
        theme    = user_data.get("theme", "light"),
        plan     = user_data.get("plan", "free"),
    )
```

### `@logout`
Clears the auth cookie. Your route decides what happens next.

```python
@app.route("/logout")
@logout
def logout_view():
    return redirect("https://easy-auth.dev/login/john_doe/my_app")
```

---

## Storing & Retrieving User Data

Every user gets a JSON key-value store on easy-auth.dev, scoped to your service. Store anything.

```python
from easyauth._config import get_connector

get_connector().send_or_update_user_data(token, {
    "theme":     "dark",
    "plan":      "pro",
    "onboarded": True,
})
```

Retrieve it automatically on any route with `@fetch_user_data` — no extra call needed.

---

## Security

easyauth doesn't cut corners on the security layer. Here's exactly what it does:

- **Fernet encryption (AES-128-CBC + HMAC-SHA256)** — tokens are encrypted before leaving the client and decrypted server-side. Plaintext tokens never exist in transit.
- **Every request is verified** — the decorator calls easy-auth.dev's verification endpoint on every hit, not just at login. A revoked or expired token is rejected immediately on the next request.
- **Cookies are `httponly`, `secure`, `SameSite=Strict`** — the token is inaccessible to JavaScript, never sent cross-site, and only transmitted over HTTPS.
- **1-hour token expiry** — enforced server-side on every request, not just at login.
- **Tampered tokens are rejected outright** — HMAC verification means a modified token doesn't silently fail validation, it hard-errors immediately.
- **Your credentials live in one place** — `configure()` or env vars. They never touch your route files.

---

## Full Working Example — Flask

```python
import easyauth
from easyauth.easyflask import login_required_redirect, fetch_user_data, logout
from easyauth._config import get_connector

from flask import Flask, render_template, redirect, request

easyauth.configure(
    username     = "john_doe",
    service_name = "my_app",
    api_key      = "your_api_key",
)

app       = Flask(__name__)
LOGIN_URL = "https://easy-auth.dev/login/john_doe/my_app"


@app.route("/")
def index():
    return redirect(LOGIN_URL)


@app.route("/dashboard")
@login_required_redirect(redirect_url=LOGIN_URL)
def dashboard(token):
    return render_template("dashboard.html")


@app.route("/profile")
@fetch_user_data
def profile(username, user_data, token):
    return render_template("profile.html", username=username, data=user_data)


@app.route("/save", methods=["POST"])
@login_required_redirect(redirect_url=LOGIN_URL)
def save(token):
    get_connector().send_or_update_user_data(token, request.json)
    return {"status": "saved"}


@app.route("/logout")
@logout
def logout_view():
    return redirect(LOGIN_URL)


if __name__ == "__main__":
    app.run(debug=True)
```

A complete, auth-protected Flask app. 40 lines including imports and blank lines.

---

## Environment Variables

| Variable                | `configure()` equivalent |
|-------------------------|--------------------------|
| `EASYAUTH_USERNAME`     | `username`               |
| `EASYAUTH_SERVICE_NAME` | `service_name`           |
| `EASYAUTH_API_KEY`      | `api_key`                |
| `EASYAUTH_BASE_URL`     | `base_url`               |

---

## Framework Support

| Framework | Install                             | Import                             |
|-----------|-------------------------------------|------------------------------------|
| All       | `pip install easy-auth-sdk`              | —                                  |
| Flask     | `pip install easy-auth-sdk[easyflask]`   | `from easyauth.easyflask import ...`   |
| FastAPI   | `pip install easy-auth-sdk[easyfastapi]` | `from easyauth.easyfastapi import ...` |
| Django    | `pip install easy-auth-sdk[easydjango]`  | `from easyauth.easydjango import ...`  |


---

## Links

- **Dashboard & services** → [easy-auth.dev](https://easy-auth.dev)
- **PyPI** → [pypi.org/project/easyauth-sdk](https://pypi.org/project/easy-auth-sdk)
- **Issues** → open an issue on GitHub
