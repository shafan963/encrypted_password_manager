#include "json.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Small input helper for this fixed demo API. It handles ordinary JSON strings
   and common escapes; it is not a general-purpose JSON parser. */
char *json_get_string(const char *json, const char *key) {
    char quoted[128], bare[128];
    const char *p, *v;
    char *out;
    size_t cap = 4096, n = 0;

    if (!json || !key) return NULL;
    if (snprintf(quoted, sizeof quoted, "\"%s\"", key) >= (int)sizeof quoted)
        return NULL;
    if (snprintf(bare, sizeof bare, "%s", key) >= (int)sizeof bare)
        return NULL;

    p = strstr(json, quoted);
    if (!p) {
        p = strstr(json, bare);
        if (!p) return NULL;
        v = strchr(p + strlen(bare), ':');
    } else {
        v = strchr(p + strlen(quoted), ':');
    }
    if (!v) return NULL;

    v++;
    while (*v == ' ' || *v == '\t' || *v == '\r' || *v == '\n') v++;
    if (*v == '"') {
        v++;
    } else if (*v == '{' || *v == '[' || *v == 'n' || *v == 't' || *v == 'f' || *v == '-' || (*v >= '0' && *v <= '9')) {
        /* This helper is intentionally strict to the fixed API: only accept string values. */
        return NULL;
    }

    out = (char *)malloc(cap);
    if (!out) return NULL;

    while (*v && *v != '"' && n + 1 < cap) {
        if (*v == '\\') {
            v++;
            if (!*v) break;
            switch (*v) {
                case 'n': out[n++] = '\n'; break;
                case 'r': out[n++] = '\r'; break;
                case 't': out[n++] = '\t'; break;
                case '"': out[n++] = '"'; break;
                case '\\': out[n++] = '\\'; break;
                case '/': out[n++] = '/'; break;
                default: out[n++] = *v; break;
            }
            v++;
        } else out[n++] = *v++;
    }
    out[n] = '\0';
    return out;
}

char *json_escape(const char *s) {
    size_t i, n = 0, cap;
    char *out;
    if (!s) s = "";
    cap = strlen(s) * 6 + 1;
    out = (char *)malloc(cap);
    if (!out) return NULL;
    for (i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') { out[n++] = '\\'; out[n++] = (char)c; }
        else if (c == '\n') { out[n++] = '\\'; out[n++] = 'n'; }
        else if (c == '\r') { out[n++] = '\\'; out[n++] = 'r'; }
        else if (c == '\t') { out[n++] = '\\'; out[n++] = 't'; }
        else if (c < 32) { n += (size_t)sprintf(out + n, "\\u%04x", c); }
        else out[n++] = (char)c;
    }
    out[n] = '\0';
    return out;
}
