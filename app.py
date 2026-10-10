import os
import secrets
from urllib.parse import urlencode

import requests
from flask import Flask, abort, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("RENDER", "").lower() == "true",
)

API = "https://discord.com/api/v10"
CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "")
BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")


def discord_headers(token):
    return {"Authorization": f"Bearer {token}"}


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.get("/")
def index():
    user = session.get("user")
    guilds = session.get("guilds", []) if user else []
    return render_template("index.html", user=user, guilds=guilds)


@app.get("/login")
def login():
    if not CLIENT_ID or not REDIRECT_URI:
        return render_template("error.html", title="Setup required", message="Discord login is not configured yet. Add DISCORD_CLIENT_ID and DISCORD_REDIRECT_URI in your Render environment variables."), 503
    session["oauth_state"] = secrets.token_urlsafe(24)
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "identify guilds",
        "state": session["oauth_state"],
        "prompt": "consent",
    }
    return redirect("https://discord.com/oauth2/authorize?" + urlencode(params))


@app.get("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")
    expected = session.pop("oauth_state", None)
    if not code or not expected or not secrets.compare_digest(state or "", expected):
        abort(400, description="The Discord login could not be verified. Please try again.")
    if not all((CLIENT_ID, CLIENT_SECRET, REDIRECT_URI)):
        abort(503, description="Discord OAuth is not configured on the server yet.")

    token_response = requests.post(
        f"{API}/oauth2/token",
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15,
    )
    if not token_response.ok:
        abort(502, description="Discord did not complete the login. Please try again.")
    access_token = token_response.json().get("access_token")
    if not access_token:
        abort(502, description="Discord did not return a login token.")

    user_response = requests.get(f"{API}/users/@me", headers=discord_headers(access_token), timeout=15)
    guild_response = requests.get(f"{API}/users/@me/guilds", headers=discord_headers(access_token), timeout=15)
    if not user_response.ok or not guild_response.ok:
        abort(502, description="Could not load your Discord account. Please try again.")

    user = user_response.json()
    guilds = guild_response.json()
    manageable = []
    for guild in guilds:
        try:
            permissions = int(guild.get("permissions", "0"))
        except (TypeError, ValueError):
            permissions = 0
        is_owner = guild.get("owner", False)
        # Administrator (8) or Manage Server (32)
        if is_owner or permissions & 8 or permissions & 32:
            manageable.append({
                "id": guild.get("id", ""),
                "name": guild.get("name", "Discord server"),
                "icon": guild.get("icon"),
                "owner": is_owner,
            })

    session.clear()
    session["user"] = {
        "id": user.get("id"),
        "username": user.get("global_name") or user.get("username", "Discord user"),
        "avatar": user.get("avatar"),
    }
    session["guilds"] = manageable
    return redirect(url_for("index"))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.get("/server/<guild_id>")
def server(guild_id):
    if not session.get("user"):
        return redirect(url_for("login"))
    guild = next((g for g in session.get("guilds", []) if g["id"] == guild_id), None)
    if guild is None:
        abort(403, description="You do not have permission to open this server from the dashboard.")
    return render_template("server.html", user=session["user"], guild=guild)


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(502)
@app.errorhandler(503)
def handled_error(error):
    return render_template("error.html", title=f"{error.code} — Something went wrong", message=getattr(error, "description", "Please try again later.")), error.code


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
