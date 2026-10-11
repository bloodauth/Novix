
import os
import secrets
from urllib.parse import urlencode

import psycopg
import requests
from psycopg.types.json import Jsonb
from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
    jsonify,
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("RENDER", "").lower() == "true",
    MAX_CONTENT_LENGTH=64 * 1024,
)

API = "https://discord.com/api/v10"

CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "")
DATABASE_URL = os.environ.get("SUPABASE_DB_URL", "")


# -------------------------
# DATABASE
# -------------------------

def discord_headers(token):
    return {"Authorization": f"Bearer {token}"}


def get_db_connection():
    if not DATABASE_URL:
        raise RuntimeError("Supabase database connection is not configured.")

    return psycopg.connect(DATABASE_URL, connect_timeout=10)


def load_guild_settings(guild_id):
    with get_db_connection() as conn:
        row = conn.execute(
            """
            SELECT settings
            FROM public.guild_settings
            WHERE guild_id = %s
            """,
            (guild_id,),
        ).fetchone()

    return row[0] if row and isinstance(row[0], dict) else {}


def save_guild_settings(guild_id, settings):
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO public.guild_settings
                (guild_id, settings, updated_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (guild_id)
            DO UPDATE SET
                settings = EXCLUDED.settings,
                updated_at = NOW()
            """,
            (guild_id, Jsonb(settings)),
        )


def get_manageable_guild(guild_id):
    if not session.get("user"):
        return None

    return next(
        (
            guild
            for guild in session.get("guilds", [])
            if guild["id"] == guild_id
        ),
        None,
    )


# -------------------------
# SECURITY HEADERS
# -------------------------

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    return response


# -------------------------
# HOME PAGE
# -------------------------

@app.get("/")
def index():
    user = session.get("user")
    guilds = session.get("guilds", []) if user else []

    return render_template(
        "index.html",
        user=user,
        guilds=guilds,
    )


# -------------------------
# DISCORD LOGIN
# -------------------------

@app.get("/login")
def login():
    if not CLIENT_ID or not REDIRECT_URI:
        app.logger.error(
            "Discord login configuration is incomplete: "
            "DISCORD_CLIENT_ID or DISCORD_REDIRECT_URI is missing."
        )

        return render_template(
            "error.html",
            title="Setup required",
            message=(
                "Discord login is not configured. "
                "Check your Render environment variables."
            ),
        ), 503

    session["oauth_state"] = secrets.token_urlsafe(24)

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "identify guilds",
        "state": session["oauth_state"],
        "prompt": "consent",
    }

    return redirect(
        "https://discord.com/oauth2/authorize?" + urlencode(params)
    )


# -------------------------
# DISCORD OAUTH CALLBACK
# -------------------------

@app.get("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")
    expected = session.pop("oauth_state", None)

    # Verify the OAuth state to protect against forged login requests.
    if (
        not code
        or not expected
        or not secrets.compare_digest(state or "", expected)
    ):
        app.logger.warning(
            "Discord OAuth callback rejected: missing code or invalid state."
        )

        abort(
            400,
            description=(
                "Discord login could not be verified. Please try again."
            ),
        )

    # Verify required environment variables.
    if not all((CLIENT_ID, CLIENT_SECRET, REDIRECT_URI)):
        app.logger.error(
            "Discord OAuth configuration is incomplete. "
            "Check the Render environment variables."
        )

        abort(
            503,
            description="Discord OAuth is not configured.",
        )

    try:
        # Exchange the authorization code for an access token.
        token_response = requests.post(
            f"{API}/oauth2/token",
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout=15,
        )

        if not token_response.ok:
            try:
                details = token_response.json()

                error_name = details.get(
                    "error",
                    "unknown_error",
                )
                error_description = details.get(
                    "error_description",
                    "No description provided",
                )

            except (ValueError, AttributeError):
                error_name = "invalid_response"
                error_description = (
                    "Discord returned a non-JSON response."
                )

            # Never log the authorization code, access token or secret.
            app.logger.error(
                "Discord OAuth token exchange failed: "
                "HTTP %s; error=%s; description=%s",
                token_response.status_code,
                error_name,
                error_description,
            )

            abort(
                502,
                description=(
                    "Discord could not complete the login. "
                    "Check the Render logs for details."
                ),
            )

        try:
            token_data = token_response.json()
        except ValueError:
            app.logger.error(
                "Discord OAuth returned an invalid token response."
            )

            abort(
                502,
                description="Discord returned an invalid login response.",
            )

        access_token = token_data.get("access_token")

        if not access_token:
            app.logger.error(
                "Discord OAuth response did not contain an access token."
            )

            abort(
                502,
                description="Discord did not return a login token.",
            )

        # Fetch the authenticated Discord user.
        user_response = requests.get(
            f"{API}/users/@me",
            headers=discord_headers(access_token),
            timeout=15,
        )

        # Fetch the user's Discord servers.
        guild_response = requests.get(
            f"{API}/users/@me/guilds",
            headers=discord_headers(access_token),
            timeout=15,
        )

        if not user_response.ok or not guild_response.ok:
            app.logger.error(
                "Discord account lookup failed: "
                "user HTTP %s; guilds HTTP %s",
                user_response.status_code,
                guild_response.status_code,
            )

            abort(
                502,
                description="Could not load your Discord account.",
            )

        try:
            user = user_response.json()
            discord_guilds = guild_response.json()
        except ValueError:
            app.logger.error(
                "Discord returned invalid JSON for the user or server list."
            )

            abort(
                502,
                description="Discord returned an invalid account response.",
            )

        # Keep servers the user owns or can administer.
        manageable = []

        for guild in discord_guilds:
            try:
                permissions = int(guild.get("permissions", "0"))
            except (TypeError, ValueError):
                permissions = 0

            is_owner = guild.get("owner", False)

            # 8 = Administrator; 32 = Manage Server.
            if is_owner or permissions & 8 or permissions & 32:
                manageable.append(
                    {
                        "id": guild.get("id", ""),
                        "name": guild.get(
                            "name",
                            "Discord server",
                        ),
                        "icon": guild.get("icon"),
                        "owner": is_owner,
                    }
                )

        # Start a fresh authenticated session.
        session.clear()

        session["user"] = {
            "id": user.get("id"),
            "username": (
                user.get("global_name")
                or user.get("username", "Discord user")
            ),
            "avatar": user.get("avatar"),
        }

        session["guilds"] = manageable

        app.logger.info(
            "Discord OAuth login completed successfully."
        )

        return redirect(url_for("index"))

    except requests.Timeout:
        app.logger.exception(
            "Timed out while communicating with Discord during OAuth."
        )

        abort(
            502,
            description="Discord took too long to respond. Please try again.",
        )

    except requests.RequestException:
        app.logger.exception(
            "Network error during the Discord OAuth callback."
        )

        abort(
            502,
            description="Could not contact Discord. Please try again.",
        )


# -------------------------
# LOGOUT
# -------------------------

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# -------------------------
# SERVER DASHBOARD
# -------------------------

@app.get("/server/<guild_id>")
def server(guild_id):
    if not session.get("user"):
        return redirect(url_for("login"))

    guild = get_manageable_guild(guild_id)

    if guild is None:
        abort(
            403,
            description="You do not have permission to open this server.",
        )

    try:
        settings = load_guild_settings(guild_id)

    except Exception:
        app.logger.exception(
            "Could not load server settings from Supabase."
        )

        abort(
            503,
            description=(
                "Could not load settings. Please try again later."
            ),
        )

    return render_template(
        "server.html",
        user=session["user"],
        guild=guild,
        settings=settings,
    )


# -------------------------
# SERVER SETTINGS API
# -------------------------

@app.route(
    "/api/server/<guild_id>/settings",
    methods=["GET", "PUT"],
)
def server_settings_api(guild_id):
    if not session.get("user"):
        return jsonify({"error": "Login required"}), 401

    if get_manageable_guild(guild_id) is None:
        return jsonify(
            {"error": "You cannot manage this server"}
        ), 403

    # Load saved settings.
    if request.method == "GET":
        try:
            settings = load_guild_settings(guild_id)

            return jsonify({"settings": settings})

        except Exception:
            app.logger.exception(
                "Could not read settings from Supabase."
            )

            return jsonify(
                {"error": "Database unavailable"}
            ), 503

    # Accept only JSON containing a settings object.
    body = request.get_json(silent=True)

    if (
        not isinstance(body, dict)
        or not isinstance(body.get("settings"), dict)
    ):
        return jsonify(
            {"error": "Send JSON with a settings object"}
        ), 400

    try:
        save_guild_settings(
            guild_id,
            body["settings"],
        )

        return jsonify({"ok": True})

    except Exception:
        app.logger.exception(
            "Could not save settings to Supabase."
        )

        return jsonify(
            {"error": "Could not save settings"}
        ), 503


# -------------------------
# ERROR PAGES
# -------------------------

@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(502)
@app.errorhandler(503)
def handled_error(error):
    return render_template(
        "error.html",
        title=f"{error.code} — Something went wrong",
        message=getattr(
            error,
            "description",
            "Please try again later.",
        ),
    ), error.code


# -------------------------
# LOCAL DEVELOPMENT
# Render uses Gunicorn, not this section.
# -------------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )
