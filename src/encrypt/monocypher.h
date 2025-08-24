#ifndef MONOCYPHER_H
#define MONOCYPHER_H

#include <stddef.h>
#include <stdint.h>

void crypto_wipe(void *secret, size_t size);


void crypto_aead_lock(uint8_t       *cipher_text,
                      uint8_t        mac  [16],
                      const uint8_t  key  [32],
                      const uint8_t  nonce[24],
                      const uint8_t *ad,         size_t ad_size,
                      const uint8_t *plain_text, size_t text_size);
int crypto_aead_unlock(uint8_t       *plain_text,
                       const uint8_t  mac  [16],
                       const uint8_t  key  [32],
                       const uint8_t  nonce[24],
                       const uint8_t *ad,          size_t ad_size,
                       const uint8_t *cipher_text, size_t text_size);

typedef struct {
	uint64_t counter;
	uint8_t  key[32];
	uint8_t  nonce[8];
} crypto_aead_ctx;

void crypto_aead_init_x(crypto_aead_ctx *ctx,
                        const uint8_t key[32], const uint8_t nonce[24]);
void crypto_aead_init_djb(crypto_aead_ctx *ctx,
                          const uint8_t key[32], const uint8_t nonce[8]);
void crypto_aead_init_ietf(crypto_aead_ctx *ctx,
                           const uint8_t key[32], const uint8_t nonce[12]);

void crypto_aead_write(crypto_aead_ctx *ctx,
                       uint8_t         *cipher_text,
                       uint8_t          mac[16],
                       const uint8_t   *ad        , size_t ad_size,
                       const uint8_t   *plain_text, size_t text_size);
int crypto_aead_read(crypto_aead_ctx *ctx,
                     uint8_t         *plain_text,
                     const uint8_t    mac[16],
                     const uint8_t   *ad        , size_t ad_size,
                     const uint8_t   *cipher_text, size_t text_size);


uint64_t crypto_chacha20_djb(uint8_t       *cipher_text,
                             const uint8_t *plain_text,
                             size_t         text_size,
                             const uint8_t  key[32],
                             const uint8_t  nonce[8],
                             uint64_t       ctr);
uint32_t crypto_chacha20_ietf(uint8_t       *cipher_text,
                              const uint8_t *plain_text,
                              size_t         text_size,
                              const uint8_t  key[32],
                              const uint8_t  nonce[12],
                              uint32_t       ctr);
uint64_t crypto_chacha20_x(uint8_t       *cipher_text,
                           const uint8_t *plain_text,
                           size_t         text_size,
                           const uint8_t  key[32],
                           const uint8_t  nonce[24],
                           uint64_t       ctr);


void crypto_poly1305(uint8_t        mac[16],
                     const uint8_t *message, size_t message_size,
                     const uint8_t  key[32]);

typedef struct {
	uint8_t  c[16];
	size_t   c_idx;
	uint32_t r  [4];
	uint32_t pad[4];
	uint32_t h  [5];
} crypto_poly1305_ctx;

void crypto_poly1305_init  (crypto_poly1305_ctx *ctx, const uint8_t key[32]);
void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
                            const uint8_t *message, size_t message_size);
void crypto_poly1305_final (crypto_poly1305_ctx *ctx, uint8_t mac[16]);

#endif /* MONOCYPHER_H */
