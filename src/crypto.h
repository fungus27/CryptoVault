#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>

#include "global_types.h"

#ifdef _DEBUG
#define handle_errors() print_errors()
#else
#define handle_errors()
#endif

extern byte salt_enc_key[16];
extern byte salt_mac_key[16];

typedef struct {
    byte enc_key[32];
    byte mac_key[32];
} key_group;

void print_errors();
void initialize();
void finalize();

u32 encrypt(byte *plaintext, u32 plaintext_len, byte *key, byte *iv, byte *ciphertext);
u32 decrypt(byte *ciphertext, u32 ciphertext_len, byte *key, byte *iv, byte *plaintext);

i32 create_hmac(byte *msg, u32 message_lenght, byte *val, EVP_PKEY *pkey);
i32 verify_hmac(byte *msg, u32 message_lenght, byte *val, EVP_PKEY *pkey);

i32 random_iv(byte* iv);
i32 random_salt(byte* salt);

void derive(byte* input, u32 input_lenght, byte* salt, byte* output, u32 iter);
void derive_master_key(byte* password, u32 password_lenght, byte* salt, byte* master_key);
void derive_child_key(byte* master_key, byte* salt, byte* child_key);

void get_keys(byte* master_key, key_group* keys);

i32 verify_key(byte* master_key, byte* token);

void generate_token(byte* key, byte* token);

#endif //CRYPTO_H