# Vital Sense API

The NVIDIA-powered backend for Vital Sense. It provides conversational replies, short chat titles, speech generation, and speech transcription through a FastAPI service.

**Owner and maintainer:** [ANURAG](https://github.com/dexterrrrrrrrrrrrrrrrrrrrr)

[Open Vital Sense](https://mindmate-ai-anurag.vercel.app) · [Frontend repository](https://github.com/dexterrrrrrrrrrrrrrrrrrrrr/MINDMATE-AI) · [Interactive API docs](https://mindmate-ai-api-anurag.onrender.com/docs) · [API reference](https://mindmate-ai-api-anurag.onrender.com/scalar_docs/)

## AI providers

- **Conversation and titles:** NVIDIA Nemotron 3 Nano Omni, through NVIDIA NIM.
- **Speech:** NVIDIA Riva and Magpie multilingual text to speech.
- **Provider configuration:** NVIDIA only; no Gemini integration or fallback.

The default chat model is `nvidia/nemotron-3-nano-omni-30b-a3b-reasoning`. Requests disable thinking output so the frontend receives the final answer. The NVIDIA speech client is pinned to a release compatible with the installed Riva library.

## Run locally

Use Python 3.11 and a valid NVIDIA API key.

```bash
git clone https://github.com/dexterrrrrrrrrrrrrrrrrrrrr/MINDMATE_AI_API.git
cd MINDMATE_AI_API
python3.11 -m venv .venv
source .venv/bin/activate
bash scripts/build.sh
cp .env.example .env
```

Fill in your private `.env` file:

```dotenv
NVIDIA_API_KEY=your_nvidia_secret_key
NVIDIA_MODEL=nvidia/nemotron-3-nano-omni-30b-a3b-reasoning
ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

Then start the service:

```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Open [localhost:8000/docs](http://127.0.0.1:8000/docs). The `.env` file is excluded from Git; never commit or put a secret key in the frontend.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/v1/` | Generate a conversational reply |
| POST | `/api/v1/convo/` | Generate a short conversation title |
| POST | `/api/v1/audio/` | Generate a WAV voice response |
| POST | `/api/v1/audio/text` | Transcribe an uploaded WAV file |
| GET, HEAD | `/health/` | Check service availability |
| GET | `/docs` | Interactive OpenAPI documentation |
| GET | `/scalar_docs/` | Scalar API reference |

### Chat

Send an array of messages. Supported roles are `user` and `model`.

```bash
curl http://127.0.0.1:8000/api/v1/ \
  -H 'Content-Type: application/json' \
  -d '[{"role":"user","content":"Help me plan a calm morning."}]'
```

The response includes `role`, `content`, and the selected `model`.

### Voice

```bash
curl http://127.0.0.1:8000/api/v1/audio/ \
  -H 'Content-Type: application/json' \
  -d '{"text":"Hello, I am Vital Sense.","voice":"Mia"}' \
  --output reply.wav
```

The response is `audio/wav`. Generated temporary audio files are removed after the response is sent.

## Deploy on Render

Use the repository root with these settings:

| Setting | Value |
| --- | --- |
| Runtime | Python 3.11 |
| Build command | `bash scripts/build.sh` |
| Start command | `uvicorn main:app --host 0.0.0.0 --port $PORT` |
| Health path | `/health/` |

Set `NVIDIA_API_KEY`, `NVIDIA_MODEL`, and `ALLOWED_ORIGINS` in the service environment. Include the deployed frontend's exact HTTPS origin in `ALLOWED_ORIGINS`. Configure `PYTHON_VERSION` in Render if pinning its Python runtime.

The current service is hosted at [mindmate-ai-api-anurag.onrender.com](https://mindmate-ai-api-anurag.onrender.com/health/), with the frontend at [mindmate-ai-anurag.vercel.app](https://mindmate-ai-anurag.vercel.app).

## Project structure

```text
ai/                   NVIDIA chat integration
routes/               Chat, title, voice, health, and documentation routes
schemas/              Request and response validation
services/             Conversation prompts and audio processing
scripts/              Dependency setup and NVIDIA speech commands
main.py               FastAPI application and CORS configuration
requirements.txt      Pinned Python dependencies
```

## Project ownership

Vital Sense API is owned and maintained in ANURAG's GitHub account as the backend for Vital Sense. Original third-party notices are preserved in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Vital Sense offers general support and information. It does not diagnose conditions or replace professional care.

## MongoDB accounts

Set `MONGODB_URI` to your MongoDB connection string and `MONGODB_DB=vital_sense` in the backend environment. Use a database user with read/write access limited to this database. Allow only your application server IP ranges in Atlas. Keep credentials out of Git and out of frontend variables. Set `COOKIE_SECURE=true` in production and `false` only for local HTTP testing.

The frontend proxies `/api/v1/account/*` to this service so sessions use same-origin HttpOnly cookies (Secure in production, SameSite=Lax). Keep the production frontend in `ALLOWED_ORIGINS`; account mutations require `X-Vital-Sense: 1` and reject unapproved origins.

- `POST /api/v1/account/signup`: name (`displayName`), email, password (10–128 characters).
- `POST /api/v1/account/login`, `POST /api/v1/account/logout`.
- `GET /api/v1/account/me`: current account; `DELETE` with password removes account and saved data.
- `GET/PUT /api/v1/account/preferences`: theme preference.
- `GET/POST /api/v1/account/records/{kind}` and `PATCH/DELETE /api/v1/account/records/{kind}/{id}` for chats, journals, goals, and moods.

Passwords use Argon2id hashes. Only SHA-256 hashes of random seven-day session tokens are stored in MongoDB. All data queries enforce ownership from the authenticated session; the browser cannot choose a user ID. Unique email and expiration indexes are initialized automatically. Login and signup attempts are limited using shared MongoDB counters. Database outages do not prevent guest AI chat from starting. Google OAuth and password-reset email delivery are deferred.

### Verify account security

Run `MONGODB_TEST_URI=mongodb://127.0.0.1:27018 .venv/bin/python -m unittest discover -s tests -v` against a disposable local MongoDB server. The tests create and remove their own uniquely named database.
