#ifndef NY_ENCRYPTION_H
#define NY_ENCRYPTION_H

#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "protocol.h"

void compute_hmac(const uint8_t* key, const uint8_t* data, size_t data_len, uint8_t* hmac);
int verify_hmac(const uint8_t* key, const uint8_t* data, size_t data_len, const uint8_t* expected_hmac);
int encrypt_payload(const uint8_t* key, const uint8_t* iv, const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len);
int decrypt_payload(const uint8_t* key, const uint8_t* iv, const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len);

#endif /* NY_ENCRYPTION_H */