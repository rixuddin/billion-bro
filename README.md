# Billion Bro

A browser-based game served from the `index.html` and `play.html` files.

Deployment: Cloudflare Workers. Production code is maintained on the `main` branch.

`worker.js` handles accounts and cloud saves under `/api/*` (D1 database `billion-bro-site`) and serves the game files as static assets. `wrangler.jsonc` holds the deploy settings, so every push to `main` redeploys both.
