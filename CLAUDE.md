# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository scope

This repository is a small Python automation project. The runnable source is intentionally concentrated in `netease_free_listen.py`; the checked-in `.github/workflows/` scripts provide the scheduled GitHub Actions wrapper. `user.json` is a runtime file and must not be treated as source code. The repository also contains no application build system, package metadata, or test suite.

The root `README.md` is the authoritative description of the eapi protocol, checkToken reverse-engineering notes, required configuration, API flow, command-line options, and GitHub Actions behavior. Keep implementation and documentation changes consistent with it.

## Development commands

Install the runtime dependencies:

```bash
python -m pip install requests pycryptodome
```

Validate the user configuration without making network requests:

```bash
python .github/workflows/inject_config.py
```

Run the main program (requires a populated local `user.json` and makes live API requests):

```bash
python netease_free_listen.py
python netease_free_listen.py --rounds 5 --watch-time 16 --delay 10
```

Run the GitHub Actions-style scheduler locally (it invokes the main script repeatedly and may sleep for long randomized intervals):

```bash
python .github/workflows/run_ads.py
```

There are currently no repository-defined lint or test commands and no test files. For a focused smoke check of pure crypto helpers, use a Python one-liner or an interactive session, for example:

```bash
python -c "from netease_free_listen import encode_check_token, decode_check_token; t=encode_check_token('B_TAG','D_TAG'); assert decode_check_token(t)=={'b':'B_TAG','r':4,'d':'D_TAG'}; print('ok')"
```

Avoid running the main program or scheduler as a test: both perform live account-affecting requests.

## Architecture

### Main program (`netease_free_listen.py`)

The module is organized as a single-file pipeline:

1. **Configuration** — `_load_user_json()` loads `user.json` relative to the script, and `Config` exposes required credentials/device fields, optional fingerprint fields, app constants, and advertising limits. `Config.validate()` is called before the network client starts.
2. **Cryptographic helpers** — `encode_check_token()` / `decode_check_token()` implement the reverse-engineered checkToken transform; `eapi_encrypt()` and `eapi_decrypt_response()` implement the AES-128-ECB eapi request/response envelope. The checkToken `b_tag` rotation index is persisted in `b_tag_state.json` (per-day, auto-reset): the server refuses a reused `b_tag` with code 2002 (one successful claim per tag per day), and the index must survive the scheduler's per-round subprocess calls. `advance_b_tag_index()` runs only after the server has judged a claim (code 200 or 2002).
3. **HTTP client** — `NetEaseEapi` owns a `requests.Session`, constructs iOS-like headers/cookies, encrypts request bodies, posts to `interface3.music.163.com`, and decrypts JSON responses. Its methods correspond to login, progress, ad retrieval, impression/click reporting, and rights claiming endpoints.
4. **Request-shaping helpers** — `_parse_json()`, context extraction, `build_ad_data_for_monitor()`, and `build_rights_claim_params()` translate the ad response into the monitor and claim payloads.
5. **Execution flow** — `run_one_round()` performs ad retrieval → impression → wait → click, then immediately claims the entitlement with the *same* ad's context (`requestId`/`contextInfo`), returning `(watch_ok, gain_ok, gain_code)`. `main()` parses CLI options, runs rounds, stops early when a claim fails, and prints a summary. Exit code 2 signals claims can no longer succeed (b_tag pool exhausted per-day or server-side refusal), which `run_ads.py` uses to stop.

When changing request fields, follow the existing response-parsing path rather than duplicating ad/context extraction. When changing limits or timing, update both the `Config` constants and the README’s documented defaults/rules.

### GitHub Actions (`.github/workflows/`)

- `free_listen.yml` runs on three hourly UTC cron entries and manual dispatch, serializes runs with the `free-listen-daily` concurrency group, installs Python 3.12 dependencies, validates configuration, and launches `run_ads.py`. It caches `b_tag_state.json` with `actions/cache` (keyed by `github.run_date`) so same-day cron runs keep rotating through fresh `b_tag`s instead of reusing a burned one.
- `run_ads.py` is the scheduler wrapper. It optionally waits a random 0–59 minutes for scheduled events, invokes the main script once per requested round, recognizes exit code 2 as “claims can no longer succeed (b_tag pool exhausted / server refusal),” and inserts short/long randomized gaps.
- `inject_config.py` is a preflight validator for `user.json`; despite its name it does not generate or inject credentials.

The workflow expects `user.json` to be supplied in the runner environment. Do not add credentials, token values, or other account-specific data to source, documentation, workflow logs, or commits. The `.gitignore` excludes `user.json` and reverse-engineering artifacts; preserve those exclusions.

## Change guidance

- Keep paths to runtime files based on `__file__`, since the workflow invokes scripts from different working directories.
- Preserve the exit-code contract: `0` for normal completion and `2` when claims can no longer succeed (per-day b_tag pool exhausted or server refusal); `run_ads.py` depends on it. Do not treat code 2002 “休息一下，请稍后再试” as a permanent daily-ad limit — it means the current `b_tag` was already used today and the rotation index must advance.
- Network changes should be exercised with the configuration validator and pure-helper smoke checks first. Full execution requires an explicitly configured account and real service access.
- There is no separate library/package boundary: importing `netease_free_listen` loads `user.json` at module import time, so tests or tooling must provide a valid runtime configuration or isolate pure helper behavior accordingly.
