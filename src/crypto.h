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

unsigned int encrypt(byte *plaintext, unsigned int plaintext_len, byte *key, byte *iv, byte *ciphertext);
unsigned int decrypt(byte *ciphertext, unsigned int ciphertext_len, byte *key, byte *iv, byte *plaintext);

int create_hmac(byte *msg, unsigned int message_lenght, byte *val, EVP_PKEY *pkey);
int verify_hmac(byte *msg, unsigned int message_lenght, byte *val, EVP_PKEY *pkey);

int random_iv(byte* iv);
int random_salt(byte* salt);

void derive(byte* input, unsigned int input_lenght, byte* salt, byte* output, unsigned int iter);
void derive_master_key(byte* password, unsigned int password_lenght, byte* salt, byte* master_key);
void derive_child_key(byte* master_key, byte* salt, byte* child_key);

void get_keys(byte* master_key, key_group* keys);

int verify_key(byte* master_key, byte* token);

void generate_token(byte* key, byte* token);

#endif //CRYPTO_H