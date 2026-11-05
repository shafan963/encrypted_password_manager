#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#define CLOSESOCK closesocket
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
typedef int socket_t;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define CLOSESOCK close
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif
#include <sqlite3.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include "crypto.h"
#include "json.h"

#ifndef PORT
#define PORT 8080
#endif
#define REQ_MAX 65536
static sqlite3 *db = NULL;
static char g_project_root[512] = ".";

static void resolve_project_root(const char *argv0, char *root, size_t cap) {
    char probe[512] = ".";
    char *slash;

    snprintf(root, cap, ".");
    if (fopen("frontend/index.html", "rb") != NULL) return;

    if (argv0 && argv0[0]) {
        snprintf(probe, sizeof probe, "%s", argv0);
        slash = strrchr(probe, '/');
        if (!slash) slash = strrchr(probe, '\\');
        if (slash) {
            *slash = '\0';
            snprintf(root, cap, "%s", probe);
        }
    }

    if (fopen("frontend/index.html", "rb") == NULL) {
        char candidate[512];
        snprintf(candidate, sizeof candidate, "%s/frontend/index.html", root);
        if (fopen(candidate, "rb") == NULL && strcmp(root, ".") != 0) {
            snprintf(candidate, sizeof candidate, "%s/../frontend/index.html", root);
            if (fopen(candidate, "rb") != NULL) {
                char *sep = strrchr(root, '/');
                if (!sep) sep = strrchr(root, '\\');
                if (sep) *sep = '\0';
            }
        }
    }
}

static void ensure_database_dir(const char *root) {
    char dir[512];
    snprintf(dir, sizeof dir, "%s/database", root);
#ifdef _WIN32
    _mkdir(dir);
#else
    mkdir(dir, 0777);
#endif
}

static int db_exec(const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}
static void send_response(socket_t s, int code, const char *type, const char *body) {
    char header[512];
    const char *status = code == 200 ? "OK" : code == 400 ? "Bad Request" :
                         code == 401 ? "Unauthorized" : code == 404 ? "Not Found" : "Server Error";
    int len = (int)strlen(body);
    snprintf(header, sizeof header,
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
        "Access-Control-Allow-Origin: http://127.0.0.1:8080\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Connection: close\r\n\r\n", code, status, type, len);
    send(s, header, (int)strlen(header), 0);
    send(s, body, len, 0);
}
static void json_reply(socket_t s, int code, const char *body) {
    send_response(s, code, "application/json; charset=utf-8", body);
}
static int get_vault(unsigned char salt[SALT_LEN], unsigned char verifier[32]) {
    sqlite3_stmt *st = NULL;
    int ok = 0;
    if (sqlite3_prepare_v2(db, "SELECT salt, verifier FROM vault_meta WHERE id=1", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == SALT_LEN && sqlite3_column_bytes(st, 1) == 32) {
        memcpy(salt, sqlite3_column_blob(st, 0), SALT_LEN);
        memcpy(verifier, sqlite3_column_blob(st, 1), 32);
        ok = 1;
    }
    sqlite3_finalize(st);
    return ok;
}
static int authenticate(const char *master, unsigned char key[KEY_LEN]) {
    unsigned char salt[SALT_LEN], expected[32], actual[32];
    int ok = 0;
    if (!master || !get_vault(salt, expected)) return 0;
    if (derive_key(master, salt, key) && make_verifier(key, actual))
        ok = CRYPTO_memcmp(expected, actual, 32) == 0;
    OPENSSL_cleanse(salt, sizeof salt);
    OPENSSL_cleanse(expected, sizeof expected);
    OPENSSL_cleanse(actual, sizeof actual);
    return ok;
}
static int username_matches(const char *username) {
    sqlite3_stmt *st = NULL;
    int matches = 0;
    if (!username || !*username ||
        sqlite3_prepare_v2(db, "SELECT username FROM vault_meta WHERE id=1", -1, &st, NULL) != SQLITE_OK)
        return 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *stored = sqlite3_column_text(st, 0);
        matches = stored && strcmp((const char *)stored, username) == 0;
    }
    sqlite3_finalize(st);
    return matches;
}
static int initialize_default_vault(void) {
    static const char default_master[] = "0000";
    static const char default_username[] = "admin";
    unsigned char salt[SALT_LEN], key[KEY_LEN], verifier[32];
    sqlite3_stmt *st = NULL;
    int ok = 0;

    if (get_vault(salt, verifier)) return 1;
    if (RAND_bytes(salt, sizeof salt) != 1 ||
        !derive_key(default_master, salt, key) ||
        !make_verifier(key, verifier)) goto done;
    if (sqlite3_prepare_v2(db, "INSERT INTO vault_meta(id,salt,verifier,username) VALUES(1,?,?,?)",
                           -1, &st, NULL) != SQLITE_OK) goto done;
    sqlite3_bind_blob(st, 1, salt, SALT_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, verifier, 32, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, default_username, -1, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;
done:
    sqlite3_finalize(st);
    OPENSSL_cleanse(salt, sizeof salt);
    OPENSSL_cleanse(key, sizeof key);
    OPENSSL_cleanse(verifier, sizeof verifier);
    return ok;
}
typedef struct {
    sqlite3_int64 id;
    unsigned char *cipher;
    int cipher_len;
} vault_entry;

static void change_master_password(socket_t s, const char *new_master,
                                   const unsigned char old_key[KEY_LEN]) {
    unsigned char salt[SALT_LEN], new_key[KEY_LEN], verifier[32];
    sqlite3_stmt *select = NULL, *update = NULL, *update_meta = NULL;
    vault_entry *items = NULL;
    size_t count = 0, capacity = 0, i;
    int transaction = 0, success = 0, code = 500;
    const char *error = "{\"error\":\"Could not change master password.\"}";

    if (!new_master || strlen(new_master) < 10) {
        json_reply(s, 400, "{\"error\":\"New master password must be at least 10 characters.\"}");
        return;
    }
    if (RAND_bytes(salt, sizeof salt) != 1 ||
        !derive_key(new_master, salt, new_key) ||
        !make_verifier(new_key, verifier)) goto done;
    if (!db_exec("BEGIN IMMEDIATE")) goto done;
    transaction = 1;
    if (sqlite3_prepare_v2(db, "SELECT id,cipher FROM entries ORDER BY id", -1, &select, NULL) != SQLITE_OK)
        goto done;

    for (;;) {
        int rc = sqlite3_step(select);
        const void *blob;
        int blob_len;
        vault_entry *grown;
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) goto done;
        blob = sqlite3_column_blob(select, 1);
        blob_len = sqlite3_column_bytes(select, 1);
        if (!blob || blob_len <= 0) goto done;
        if (count == capacity) {
            size_t new_capacity = capacity ? capacity * 2 : 16;
            grown = (vault_entry *)realloc(items, new_capacity * sizeof *items);
            if (!grown) goto done;
            items = grown;
            capacity = new_capacity;
        }
        items[count].cipher = (unsigned char *)malloc((size_t)blob_len);
        if (!items[count].cipher) goto done;
        memcpy(items[count].cipher, blob, (size_t)blob_len);
        items[count].cipher_len = blob_len;
        items[count].id = sqlite3_column_int64(select, 0);
        count++;
    }
    sqlite3_finalize(select);
    select = NULL;

    if (sqlite3_prepare_v2(db, "UPDATE entries SET cipher=? WHERE id=?", -1, &update, NULL) != SQLITE_OK)
        goto done;
    for (i = 0; i < count; i++) {
        char *plain = NULL;
        unsigned char *new_cipher = NULL;
        int new_cipher_len = 0;
        int step_ok;
        if (!decrypt_text(old_key, items[i].cipher, items[i].cipher_len, &plain) ||
            !encrypt_text(new_key, plain, &new_cipher, &new_cipher_len)) {
            if (plain) { OPENSSL_cleanse(plain, strlen(plain)); free(plain); }
            if (new_cipher) { OPENSSL_cleanse(new_cipher, new_cipher_len); free(new_cipher); }
            goto done;
        }
        sqlite3_reset(update);
        sqlite3_clear_bindings(update);
        sqlite3_bind_blob(update, 1, new_cipher, new_cipher_len, SQLITE_TRANSIENT);
        sqlite3_bind_int64(update, 2, items[i].id);
        step_ok = sqlite3_step(update) == SQLITE_DONE && sqlite3_changes(db) == 1;
        OPENSSL_cleanse(plain, strlen(plain));
        free(plain);
        OPENSSL_cleanse(new_cipher, (size_t)new_cipher_len);
        free(new_cipher);
        if (!step_ok) goto done;
    }

    if (sqlite3_prepare_v2(db, "UPDATE vault_meta SET salt=?,verifier=? WHERE id=1",
                           -1, &update_meta, NULL) != SQLITE_OK) goto done;
    sqlite3_bind_blob(update_meta, 1, salt, SALT_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(update_meta, 2, verifier, 32, SQLITE_TRANSIENT);
    if (sqlite3_step(update_meta) != SQLITE_DONE || sqlite3_changes(db) != 1) goto done;
    if (!db_exec("COMMIT")) goto done;
    transaction = 0;
    success = 1;
done:
    sqlite3_finalize(select);
    sqlite3_finalize(update);
    sqlite3_finalize(update_meta);
    if (transaction) db_exec("ROLLBACK");
    for (i = 0; i < count; i++) {
        OPENSSL_cleanse(items[i].cipher, (size_t)items[i].cipher_len);
        free(items[i].cipher);
    }
    free(items);
    OPENSSL_cleanse(salt, sizeof salt);
    OPENSSL_cleanse(new_key, sizeof new_key);
    OPENSSL_cleanse(verifier, sizeof verifier);
    if (success) json_reply(s, 200, "{\"ok\":true}");
    else json_reply(s, code, error);
}
static void handle_api(socket_t s, const char *method, const char *path, const char *body) {
    char *master = json_get_string(body, "master");
    char *login_name = json_get_string(body, "login");
    char *new_master = NULL;
    if (strcmp(method, "OPTIONS") == 0) { json_reply(s, 200, "{}"); goto done; }

    if (strcmp(path, "/api/status") == 0) {
        unsigned char a[SALT_LEN], b[32];
        json_reply(s, 200, get_vault(a, b) ? "{\"initialized\":true}" : "{\"initialized\":false}");
        OPENSSL_cleanse(a, sizeof a); OPENSSL_cleanse(b, sizeof b);
        goto done;
    }

    if (strcmp(path, "/api/setup") == 0) {
        unsigned char salt[SALT_LEN], key[KEY_LEN], verifier[32];
        sqlite3_stmt *st = NULL;
        char *m = master;
        if (!login_name || !*login_name || strlen(login_name) > 255) { json_reply(s, 400, "{\"error\":\"A login name of at most 255 characters is required.\"}"); goto done; }
        if (!m || strlen(m) < 10) { json_reply(s, 400, "{\"error\":\"Master password must be at least 10 characters.\"}"); goto done; }
        if (get_vault(salt, verifier)) { json_reply(s, 400, "{\"error\":\"Vault already exists. Please sign in.\"}"); goto done; }
        if (RAND_bytes(salt, sizeof salt) != 1 || !derive_key(m, salt, key) || !make_verifier(key, verifier)) {
            json_reply(s, 500, "{\"error\":\"Could not initialize encryption.\"}"); goto setup_done;
        }
        if (sqlite3_prepare_v2(db, "INSERT INTO vault_meta(id,salt,verifier,username) VALUES(1,?,?,?)", -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(st, 1, salt, SALT_LEN, SQLITE_TRANSIENT);
            sqlite3_bind_blob(st, 2, verifier, 32, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, login_name, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_DONE) json_reply(s, 200, "{\"ok\":true}");
            else json_reply(s, 500, "{\"error\":\"Database write failed.\"}");
        } else json_reply(s, 500, "{\"error\":\"Database error.\"}");
        sqlite3_finalize(st);
setup_done:
        OPENSSL_cleanse(salt, sizeof salt); OPENSSL_cleanse(key, sizeof key); OPENSSL_cleanse(verifier, sizeof verifier);
        goto done;
    }

    if (strcmp(path, "/api/login") == 0 || strcmp(path, "/api/list") == 0 ||
        strcmp(path, "/api/add") == 0 || strcmp(path, "/api/delete") == 0 ||
        strcmp(path, "/api/change-master") == 0) {
        unsigned char key[KEY_LEN];
        if (!username_matches(login_name) || !authenticate(master, key)) {
            json_reply(s, 401, "{\"error\":\"Incorrect login name or master password.\"}");
            goto done;
        }

        if (strcmp(path, "/api/login") == 0) {
            json_reply(s, 200, "{\"ok\":true}");
        } else if (strcmp(path, "/api/change-master") == 0) {
            new_master = json_get_string(body, "newMaster");
            change_master_password(s, new_master, key);
        } else if (strcmp(path, "/api/add") == 0) {
            char *site = json_get_string(body, "site");
            char *username = json_get_string(body, "username");
            char *password = json_get_string(body, "password");
            unsigned char *cipher = NULL;
            int cipher_len = 0;
            sqlite3_stmt *st = NULL;
            if (!site || !*site || !username || !password || !*password) {
                json_reply(s, 400, "{\"error\":\"Website, username and password are required.\"}");
            } else if (!encrypt_text(key, password, &cipher, &cipher_len)) {
                json_reply(s, 500, "{\"error\":\"Encryption failed.\"}");
            } else if (sqlite3_prepare_v2(db, "INSERT INTO entries(site,username,cipher,created_at) VALUES(?,?,?,?)", -1, &st, NULL) != SQLITE_OK) {
                json_reply(s, 500, "{\"error\":\"Database error.\"}");
            } else {
                sqlite3_bind_text(st, 1, site, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 2, username, -1, SQLITE_TRANSIENT);
                sqlite3_bind_blob(st, 3, cipher, cipher_len, SQLITE_TRANSIENT);
                sqlite3_bind_int64(st, 4, (sqlite3_int64)time(NULL));
                if (sqlite3_step(st) == SQLITE_DONE) json_reply(s, 200, "{\"ok\":true}");
                else json_reply(s, 500, "{\"error\":\"Could not save entry.\"}");
            }
            sqlite3_finalize(st); if (cipher) { OPENSSL_cleanse(cipher, cipher_len); free(cipher); }
            free(site); free(username); if (password) { OPENSSL_cleanse(password, strlen(password)); free(password); }
        } else if (strcmp(path, "/api/list") == 0) {
            sqlite3_stmt *st = NULL;
            char *out = (char *)calloc(1, 60000);
            int first = 1, failed = 0;
            if (!out) { json_reply(s, 500, "{\"error\":\"Out of memory.\"}"); }
            else {
                strcpy(out, "{\"entries\":[");
                if (sqlite3_prepare_v2(db, "SELECT id,site,username,cipher FROM entries ORDER BY id DESC", -1, &st, NULL) == SQLITE_OK) {
                    while (sqlite3_step(st) == SQLITE_ROW) {
                        char *site = json_escape((const char *)sqlite3_column_text(st, 1));
                        char *user = json_escape((const char *)sqlite3_column_text(st, 2));
                        char *pass = NULL, *epass = NULL;
                        const unsigned char *blob = (const unsigned char *)sqlite3_column_blob(st, 3);
                        int blen = sqlite3_column_bytes(st, 3);
                        char item[8192];
                        if (!decrypt_text(key, blob, blen, &pass)) { failed = 1; free(site); free(user); break; }
                        epass = json_escape(pass);
                        snprintf(item, sizeof item, "%s{\"id\":%d,\"site\":\"%s\",\"username\":\"%s\",\"password\":\"%s\"}",
                                 first ? "" : ",", sqlite3_column_int(st, 0), site ? site : "", user ? user : "", epass ? epass : "");
                        if (strlen(out) + strlen(item) + 32 >= 60000) { failed = 1; }
                        else strcat(out, item);
                        first = 0;
                        OPENSSL_cleanse(pass, strlen(pass)); free(pass); free(site); free(user); free(epass);
                        if (failed) break;
                    }
                } else failed = 1;
                sqlite3_finalize(st);
                strcat(out, "]}");
                json_reply(s, failed ? 500 : 200, failed ? "{\"error\":\"Could not decrypt vault entry.\"}" : out);
                OPENSSL_cleanse(out, strlen(out)); free(out);
            }
        } else if (strcmp(path, "/api/delete") == 0) {
            char *idstr = json_get_string(body, "id");
            int id = idstr ? atoi(idstr) : 0;
            sqlite3_stmt *st = NULL;
            if (id <= 0) json_reply(s, 400, "{\"error\":\"Invalid entry ID.\"}");
            else if (sqlite3_prepare_v2(db, "DELETE FROM entries WHERE id=?", -1, &st, NULL) != SQLITE_OK)
                json_reply(s, 500, "{\"error\":\"Database error.\"}");
            else {
                int rc;
                sqlite3_bind_int(st, 1, id);
                rc = sqlite3_step(st);
                if (rc == SQLITE_DONE) json_reply(s, 200, "{\"ok\":true}");
                else json_reply(s, 500, "{\"error\":\"Could not delete entry.\"}");
            }
            sqlite3_finalize(st); free(idstr);
        }
        OPENSSL_cleanse(key, sizeof key);
        goto done;
    }
    json_reply(s, 404, "{\"error\":\"Not found.\"}");
done:
    if (master) { OPENSSL_cleanse(master, strlen(master)); free(master); }
    free(login_name);
    if (new_master) { OPENSSL_cleanse(new_master, strlen(new_master)); free(new_master); }
}

static int ensure_username_column(void) {
    sqlite3_stmt *st = NULL;
    int found = 0;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(vault_meta)", -1, &st, NULL) != SQLITE_OK)
        return 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 1);
        if (name && strcmp((const char *)name, "username") == 0) {
            found = 1;
            break;
        }
    }
    sqlite3_finalize(st);
    return found || db_exec("ALTER TABLE vault_meta ADD COLUMN username TEXT NOT NULL DEFAULT 'admin'");
}

static void serve_file(socket_t s, const char *path) {
    const char *file = "frontend/index.html", *type = "text/html; charset=utf-8";
    char full[512], header[512], *data;
    FILE *fp;
    long size;
    if (strcmp(path, "/style.css") == 0) { file = "frontend/style.css"; type = "text/css; charset=utf-8"; }
    else if (strcmp(path, "/script.js") == 0) { file = "frontend/script.js"; type = "application/javascript; charset=utf-8"; }
    else if (strcmp(path, "/") != 0 && strcmp(path, "/index.html") != 0) {
        send_response(s, 404, "text/plain", "Not found"); return;
    }
    snprintf(full, sizeof full, "%s/%s", g_project_root, file);
    fp = fopen(full, "rb");
    if (!fp) { send_response(s, 500, "text/plain", "Could not open frontend file. Run the server from the project root folder."); return; }
    fseek(fp, 0, SEEK_END); size = ftell(fp); rewind(fp);
    data = (char *)malloc((size_t)size + 1);
    if (!data) { fclose(fp); send_response(s, 500, "text/plain", "Out of memory"); return; }
    fread(data, 1, (size_t)size, fp); fclose(fp); data[size] = 0;
    snprintf(header, sizeof header,
        "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %ld\r\nConnection: close\r\n\r\n", type, size);
    send(s, header, (int)strlen(header), 0); send(s, data, (int)size, 0); free(data);
}

int main(int argc, char **argv) {
    char db_path[512];
    (void)argc;
    resolve_project_root(argv[0], g_project_root, sizeof g_project_root);
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) { fprintf(stderr, "Winsock startup failed\n"); return 1; }
#endif
    ensure_database_dir(g_project_root);
    snprintf(db_path, sizeof db_path, "%s/database/passwords.db", g_project_root);
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Could not open database: %s\n", sqlite3_errmsg(db)); return 1;
    }
    if (!db_exec("CREATE TABLE IF NOT EXISTS vault_meta(id INTEGER PRIMARY KEY CHECK(id=1), salt BLOB NOT NULL, verifier BLOB NOT NULL, username TEXT NOT NULL DEFAULT 'admin')") ||
        !ensure_username_column() ||
        !db_exec("CREATE TABLE IF NOT EXISTS entries(id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT NOT NULL, username TEXT NOT NULL, cipher BLOB NOT NULL, created_at INTEGER NOT NULL)")) {
        fprintf(stderr, "Could not initialize the database schema: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }
    if (!initialize_default_vault()) {
        fprintf(stderr, "Could not initialize the default vault.\n");
        sqlite3_close(db);
        return 1;
    }

    socket_t server = socket(AF_INET, SOCK_STREAM, 0);
    if (server == INVALID_SOCKET) { fprintf(stderr, "Socket creation failed\n"); return 1; }
    int opt = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof opt);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET; addr.sin_port = htons(PORT); addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(server, (struct sockaddr *)&addr, sizeof addr) == SOCKET_ERROR || listen(server, 10) == SOCKET_ERROR) {
        fprintf(stderr, "Could not bind to 127.0.0.1:%d. Is another server using this port?\n", PORT); return 1;
    }
    printf("ENCRYPT Password Manager running at http://127.0.0.1:%d\n", PORT);
    printf("Keep this terminal open. Press Ctrl+C to stop.\n");
    for (;;) {
        socket_t client = accept(server, NULL, NULL);
        if (client == INVALID_SOCKET) continue;
        char *req = (char *)calloc(1, REQ_MAX + 1);
        if (req) {
            int got = 0, n, content_len = 0;
            while (got < REQ_MAX && (n = recv(client, req + got, REQ_MAX - got, 0)) > 0) {
                got += n; req[got] = '\0';
                char *head_end = strstr(req, "\r\n\r\n");
                if (head_end) {
                    char *cl = strstr(req, "Content-Length:");
                    if (cl) {
                        char *p = cl + strlen("Content-Length:");
                        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
                        content_len = atoi(p);
                    }
                    if (content_len > 0 && got >= (int)(head_end + 4 - req) + content_len) break;
                    if (content_len == 0) break;
                }
            }
            char method[16] = "", path[256] = "";
            sscanf(req, "%15s %255s", method, path);
            char *body = strstr(req, "\r\n\r\n");
            if (body) {
                body += 4;
                if (content_len > 0 && (size_t)(body - req) + (size_t)content_len <= REQ_MAX) {
                    body[content_len] = '\0';
                }
            } else {
                body = "";
            }
            if (strncmp(path, "/api/", 5) == 0) handle_api(client, method, path, body);
            else if (strcmp(method, "GET") == 0) serve_file(client, path);
            else json_reply(client, 400, "{\"error\":\"Bad request.\"}");
            free(req);
        }
        CLOSESOCK(client);
    }
    CLOSESOCK(server);
    sqlite3_close(db);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
