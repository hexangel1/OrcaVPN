#ifndef ENCRYPTION_H_SENTRY
#define ENCRYPTION_H_SENTRY

#include <stddef.h>

typedef struct crypto_key_st crypto_key;

typedef enum crypto_key_type_en {
	aes_hmac_sha1,
	xchacha20_poly1305
} crypto_key_type;

/* Init encryption module */
void init_encryption(void);

/* Read random bytes from /dev/urandom to buffer */
int read_random(void *buf, size_t len);

/* Allocate crypto key */
crypto_key *crypto_key_create(const void *cipher_key, int keylen,
	crypto_key_type cipher);
/* Free crypto key */
void crypto_key_destroy(crypto_key *crkey);
/* Parse crypto key parse cipher string */
crypto_key_type crypto_key_parse_cipher(const char *str);

/* Encrypt message */
void encrypt_message(void *mesg, size_t *len, const crypto_key *crkey);
/* Decrypt message */
int decrypt_message(void *mesg, size_t *len, const crypto_key *crkey);

#endif /* ENCRYPTION_H_SENTRY */
