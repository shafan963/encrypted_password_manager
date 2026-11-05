#ifndef ENCRYPT_CRYPTO_H
#define ENCRYPT_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define SALT_LEN 16
#define KEY_LEN 32
#define NONCE_LEN 12
#define TAG_LEN 16

int derive_key(const char *master, const unsigned char salt[SALT_LEN],
               unsigned char key[KEY_LEN]);
int make_verifier(const unsigned char key[KEY_LEN], unsigned char out[32]);
int encrypt_text(const unsigned char key[KEY_LEN], const char *plain,
                 unsigned char **blob, int *blob_len);
int decrypt_text(const unsigned char key[KEY_LEN], const unsigned char *blob,
                 int blob_len, char **plain);

#endif
