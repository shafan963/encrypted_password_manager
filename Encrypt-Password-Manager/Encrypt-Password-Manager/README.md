# ENCRYPT — C-Based Password Manager

A local educational password-manager project with a C HTTP backend, SQLite storage,
OpenSSL PBKDF2-HMAC-SHA256 key derivation, and AES-256-GCM authenticated encryption.

## Requirements (Windows)
- VS Code
- MSYS2 UCRT64 environment
- GCC, CMake, OpenSSL and SQLite development packages

Install in the **MSYS2 UCRT64** terminal:
```bash
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-sqlite3
```

## Build
Open the project folder in VS Code. Use the MSYS2 UCRT64 terminal:
```bash
cmake -S . -B build -G "MinGW Makefiles" \
  -DOPENSSL_ROOT_DIR=/ucrt64 \
  -DSQLite3_INCLUDE_DIR=/ucrt64/include \
  -DSQLite3_LIBRARY=/ucrt64/lib/libsqlite3.dll.a
cmake --build build
```

Run:
```bash
./build/encrypt_server.exe
```
Then open http://127.0.0.1:8080

If Windows cannot find OpenSSL/SQLite DLLs, run the server from the MSYS2 UCRT64
terminal, where `/ucrt64/bin` is already on PATH.

## First use
1. The server creates a vault with the default login name `admin` and master password `0000` if no vault exists.
2. Sign in with `admin` and `0000`, then choose **Change master password** and set a strong
   password of at least 10 characters. The change form re-encrypts saved entries.
3. Sign in with your new master password on later runs.
4. Add website credentials. The C backend encrypts each password before it is
   written to SQLite.
5. Use the search box to filter entries, and the eye/copy/delete controls to manage them.

The default login name `admin` and password `0000` are intentionally weak and are only suitable for this local
demonstration. Change it before storing any credentials. Existing vaults keep
their current master password; sign in with it and use **Change master password**.

## Public sample demo on Render

The included `render.yaml` deploys only the static frontend as a public, sample-data
demo. It does not deploy the C backend or a database. The demo uses fake credentials;
entries added in the browser are discarded when the page is refreshed. Never enter
real passwords on the public demo.

To publish it, push this project to a GitHub repository, create a Render account,
and choose **New → Blueprint** to connect the repository and apply `render.yaml`.
Render will provide a free `onrender.com` address. The free PostgreSQL service is
not used: Render's free databases expire after 30 days, so they are unsuitable for
storing a real password vault. A real private cloud vault needs persistent storage
and additional security work; this demo deployment is not that.

## Important security limitations
This is a local college-project demonstration, not a production password manager.
The server binds only to 127.0.0.1. Requests use plain HTTP on loopback and the
master password is sent to the local C process. Do not expose this server to a
network or use it for real/high-value credentials. A production system needs
independent security review, HTTPS, robust session/key handling, rate limiting,
CSRF protections, secure memory handling, and a carefully designed recovery flow.
The demo keeps the derived key only in browser memory and sends the master password
with API calls; it is intentionally simple for learning and should not be deployed.
