#ifndef ENCRYPTION_H_SENTRY
#define ENCRYPTION_H_SENTRY

#include <stddef.h>

typedef struct crypto_key_st crypto_key;

/* Init encryption module */
void init_encryption(void);

/* Read random bytes from /dev/urandom to buffer */
int read_random(void *buf, size_t len);

/* Allocate crypto key */
crypto_key *crypto_key_create(const void *cipher_key, int keylen);
/* Free crypto key */
void crypto_key_destroy(crypto_key *crkey);

/* Encrypt message */
void encrypt_message(void *mesg, size_t *len, const crypto_key *crkey);
/* Decrypt message */
int decrypt_message(void *mesg, size_t *len, const crypto_key *crkey);

#endif /* ENCRYPTION_H_SENTRY */
