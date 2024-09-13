#ifndef AES_H_SENTRY
#define AES_H_SENTRY

#include <stddef.h>
#include <stdint.h>

/* Initialize AES variables */
void aes_init(size_t key_size);
/* Performs AES round keys generation */
uint8_t *aes_key_expansion(const uint8_t *key, uint8_t *w);
/* Performs AES cipher operation */
void aes_cipher(const uint8_t *in, uint8_t *out, const uint8_t *w);
/* Performs AES inverse cipher operation */
void aes_inv_cipher(const uint8_t *in, uint8_t *out, const uint8_t *w);

#endif /* AES_H_SENTRY */
