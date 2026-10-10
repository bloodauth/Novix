# Novix Dashboard

A Flask starter dashboard for Novix with Discord OAuth2 sign-in and a server selector. This starter does **not** yet control the bot; moderation, AutoMod and ticket settings are placeholders until a secure bot integration is added.

## Deploy to Render

1. Push these files to a private GitHub repository.
2. In Render, choose **New + → Web Service**, connect the repository, and use:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app --workers 2 --bind 0.0.0.0:$PORT`
3. Add environment variables in Render:
   - `FLASK_SECRET_KEY`: a long random secret (Render's `render.yaml` can generate one)
   - `DISCORD_CLIENT_ID`: Application ID from the Discord Developer Portal
   - `DISCORD_CLIENT_SECRET`: OAuth2 client secret
   - `DISCORD_REDIRECT_URI`: `https://YOUR-RENDER-SERVICE.onrender.com/callback`
   - `DISCORD_BOT_TOKEN`: optional for future bot features; never put this in frontend JavaScript
4. In Discord Developer Portal → your application → OAuth2, add the exact same redirect URL.
5. Deploy and open the Render URL.

## Security notes

- Never commit `.env` or publish Discord client secrets / bot tokens.
- OAuth asks for `identify` and `guilds` only. The dashboard filters servers to those where the user owns the server or has Administrator / Manage Server permissions.
- Use HTTPS in production. Render provides HTTPS on its service domain.
- Before adding controls that modify server or bot settings, add server-side authorization checks for every action.
