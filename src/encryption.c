#include "encryption.h"
#include "protocol.h"
#include <string.h>

void compute_hmac(const uint8_t* key, const uint8_t* data, size_t data_len, uint8_t* hmac) {
    LOG("DEBUG", "Computing HMAC for data of length %zu", data_len);
    HMAC(EVP_sha256(), key, KEY_LENGTH, data, data_len, hmac, NULL);
    LOG("DEBUG", "HMAC computation completed");
}

int verify_hmac(const uint8_t* key, const uint8_t* data, size_t data_len, const uint8_t* expected_hmac) {
    LOG("DEBUG", "Verifying HMAC for data of length %zu", data_len);
    uint8_t computed_hmac[HMAC_LENGTH];
    compute_hmac(key, data, data_len, computed_hmac);
    int result = memcmp(computed_hmac, expected_hmac, HMAC_LENGTH) == 0;
    LOG("DEBUG", "HMAC verification %s", result ? "succeeded" : "failed");
    return result;
}

int encrypt_payload(const uint8_t* key, const uint8_t* iv, const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len) {
    LOG("DEBUG", "Starting payload encryption for %zu bytes", in_len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG("ERROR", "Failed to create EVP_CIPHER_CTX for encryption");
        return -1;
    }
    LOG("DEBUG", "EVP_CIPHER_CTX created successfully");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        LOG("ERROR", "EVP_EncryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    LOG("DEBUG", "Encryption initialized with AES-256-CBC");

    int len, total_len = 0;
    if (EVP_EncryptUpdate(ctx, out, &len, in, in_len) != 1) {
        LOG("ERROR", "EVP_EncryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;
    LOG("DEBUG", "Encrypted %d bytes in update step", len);

    if (EVP_EncryptFinal_ex(ctx, out + len, &len) != 1) {
        LOG("ERROR", "EVP_EncryptFinal_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;
    LOG("DEBUG", "Finalized encryption, added %d bytes, total %zu bytes", len, total_len);

    EVP_CIPHER_CTX_free(ctx);
    *out_len = total_len;
    LOG("DEBUG", "Encryption completed successfully, output length %zu bytes", *out_len);
    return 0;
}

int decrypt_payload(const uint8_t* key, const uint8_t* iv, const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len) {
    LOG("DEBUG", "Starting payload decryption for %zu bytes", in_len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG("ERROR", "Failed to create EVP_CIPHER_CTX for decryption");
        return -1;
    }
    LOG("DEBUG", "EVP_CIPHER_CTX created successfully for decryption");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        LOG("ERROR", "EVP_DecryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    LOG("DEBUG", "Decryption initialized with AES-256-CBC");

    int len, total_len = 0;
    if (EVP_DecryptUpdate(ctx, out, &len, in, in_len) != 1) {
        LOG("ERROR", "EVP_DecryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;
    LOG("DEBUG", "Decrypted %d bytes in update step", len);

    if (EVP_DecryptFinal_ex(ctx, out + len, &len) != 1) {
        LOG("ERROR", "EVP_DecryptFinal_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;
    LOG("DEBUG", "Finalized decryption, added %d bytes, total %zu bytes", len, total_len);

    EVP_CIPHER_CTX_free(ctx);
    *out_len = total_len;
    LOG("DEBUG", "Decryption completed successfully, output length %zu bytes", *out_len);
    return 0;
}