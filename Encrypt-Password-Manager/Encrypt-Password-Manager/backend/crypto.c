#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

int derive_key(const char *master, const unsigned char salt[SALT_LEN],
               unsigned char key[KEY_LEN]) {
    if (!master || strlen(master) < 4) return 0;
    return PKCS5_PBKDF2_HMAC(master, (int)strlen(master), salt, SALT_LEN,
                             600000, EVP_sha256(), KEY_LEN, key) == 1;
}

int make_verifier(const unsigned char key[KEY_LEN], unsigned char out[32]) {
    unsigned int len = 0;
    return HMAC(EVP_sha256(), key, KEY_LEN,
                (const unsigned char *)"ENCRYPT vault verifier v1", 24,
                out, &len) != NULL && len == 32;
}

/* Blob layout: 12-byte nonce | 16-byte GCM tag | ciphertext */
int encrypt_text(const unsigned char key[KEY_LEN], const char *plain,
                 unsigned char **blob, int *blob_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char nonce[NONCE_LEN], tag[TAG_LEN];
    int n = 0, total = 0, plen = (int)strlen(plain);
    unsigned char *out = NULL;
    int ok = 0;

    if (RAND_bytes(nonce, sizeof nonce) != 1) return 0;
    out = (unsigned char *)malloc(NONCE_LEN + TAG_LEN + plen + 1);
    if (!out) return 0;
    memcpy(out, nonce, NONCE_LEN);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto done;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, out + NONCE_LEN + TAG_LEN, &n,
                          (const unsigned char *)plain, plen) != 1) goto done;
    total = n;
    if (EVP_EncryptFinal_ex(ctx, out + NONCE_LEN + TAG_LEN + total, &n) != 1) goto done;
    total += n;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) goto done;
    memcpy(out + NONCE_LEN, tag, TAG_LEN);
    *blob = out;
    *blob_len = NONCE_LEN + TAG_LEN + total;
    out = NULL;
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    free(out);
    OPENSSL_cleanse(nonce, sizeof nonce);
    OPENSSL_cleanse(tag, sizeof tag);
    return ok;
}

int decrypt_text(const unsigned char key[KEY_LEN], const unsigned char *blob,
                 int blob_len, char **plain) {
    EVP_CIPHER_CTX *ctx = NULL;
    int n = 0, total = 0, clen;
    char *out = NULL;
    int ok = 0;
    if (!blob || blob_len < NONCE_LEN + TAG_LEN) return 0;
    clen = blob_len - NONCE_LEN - TAG_LEN;
    out = (char *)calloc((size_t)clen + 1, 1);
    if (!out) return 0;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto done;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, blob) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, (unsigned char *)out, &n,
                          blob + NONCE_LEN + TAG_LEN, clen) != 1) goto done;
    total = n;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                            (void *)(blob + NONCE_LEN)) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)out + total, &n) != 1) goto done;
    total += n;
    out[total] = '\0';
    *plain = out;
    out = NULL;
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    if (out) { OPENSSL_cleanse(out, (size_t)clen + 1); free(out); }
    return ok;
}
