# Portio

A Backend for Frontend (BFF) and reverse proxy in .NET 10, built on YARP. It is the only public door of the
platform: it ends HTTPS, serves the dashboard, runs the login, keeps the session and forwards API calls to the
services with the user's access token.

The point of it: **the browser never holds a token.** It gets a session cookie it can't read, and nothing else.

## What it does

| Path | What happens |
| --- | --- |
| `GET /bff/login` | Creates state + PKCE, remembers them in an encrypted cookie, redirects to `/api/OIDC/authorize` |
| `/api/OIDC/...`, `/api/auth/google/callback` | Projectio's login endpoints, passed through. The browser never talks to Projectio directly |
| `GET /bff/callback` | Checks state, swaps the one-time code for tokens (server to server), starts the session |
| `GET /bff/user` | Who is logged in. 401 means nobody |
| `GET /bff/csrf-token` | The token the app sends back in `X-XSRF-TOKEN` |
| `POST /bff/logout` | Revokes the refresh token, deletes the session |
| `/api/ml/...` | Forwarded to OrchestrML as `/api/v1/...` with `Authorization: Bearer <access token>` |
| `/api/account/...` | Forwarded to Projectio the same way |
| `/api/v1/ml_jobs/jobs/predict/api-key` | Forwarded to OrchestrML as it is, for machine clients that send an `X-API-Key` header instead of a session |
| everything else | The dashboard's files |

## How the session works

- The cookie holds a random 256-bit session id, nothing else. `__Host-` prefix, HttpOnly, Secure, SameSite=Strict.
- The session (access token, refresh token, expiry) is encrypted with ASP.NET Data Protection and stored
  under the SHA-256 hash of the id: in Redis when `Redis__Configuration` is set, otherwise in memory.
- It ends after 1 hour without requests, or 8 hours after login.
- The access token is refreshed 30 seconds before it expires. Refresh tokens work only once, so requests of
  one session refresh one at a time (see `SessionMiddleware`).
- Every POST, PUT, PATCH and DELETE needs the CSRF token, on Portio's own endpoints and on the forwarded ones.
  The exception are the public paths (`Auth__PublicPaths`): on Projectio's login endpoints Google posts the login
  result from its own site, and machine clients send an API key, not a cookie.

## Configuration

`appsettings.json` has the development defaults. Secrets go into a `.env` file next to `Portio.csproj`
(`Portio/.env`). `.env.example` shows what goes in it.

| Setting | Meaning |
| --- | --- |
| `Auth__Authority` | Where Portio reaches Projectio |
| `Auth__ClientId`, `Auth__ClientSecret` | Portio's registration at Projectio |
| `Auth__RedirectUri` | Portio's public callback address, must match the registration |
| `Auth__FrontendUrl` | Where the browser goes after login (Portio's public address) |
| `Auth__PublicPaths` | The only `/api` paths that work without a session: Projectio's login endpoints and the API-key endpoint |
| `Redis__Configuration` | Redis for the sessions (optional) |
| `DataProtection__KeysPath` | Folder for the encryption keys. Needed in a container, otherwise a restart logs everyone out |
| `Uploads__MaxMegabytes` | Largest request Portio accepts (default 200). Dataset uploads pass through Portio |
| `ReverseProxy__...` | Routes and addresses of the services (YARP) |
| `ASPNETCORE_HTTPS_PORTS`, `ASPNETCORE_Kestrel__Certificates__Default__Path` / `__Password` | HTTPS port and certificate in a container (see `docker-compose.yml`) |

## Run

```
dotnet run --project Portio --launch-profile https
```

Open https://localhost:7287. Projectio has to run on https://localhost:7256 and the dashboard's dev server on
http://localhost:5173. The whole platform with Docker: see `README-DOCKER.md` of the platform.
