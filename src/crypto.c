#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "crypto.h"

#define DERIVE_FUNCTION EVP_sha256()

#define N_ITERATIONS_MASTER 300000
#define N_ITERATIONS_CHILD 10000
#define N_ITERATIONS_TOKEN 10000

byte salt_enc_key[16] = {50, 156, 173, 242, 26, 90, 239, 246, 139, 216, 70, 53, 254, 1, 198, 43};
byte salt_mac_key[16] = {38, 201, 151, 231, 208, 219, 244, 17, 111, 186, 53, 122, 21, 239, 173, 155};

static byte salt_token[16] = {56, 126, 187, 55, 30, 216, 136, 56, 98, 159, 162, 202, 117, 13, 74, 144};

void print_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

void initialize(){
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
}

void finalize(){
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

unsigned int encrypt(byte *plaintext, unsigned int plaintext_len, byte *key, byte *iv, byte *ciphertext){
    EVP_CIPHER_CTX *ctx;
    unsigned int len;
    unsigned int ciphertext_len;
    
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handle_errors();
    
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_errors();
    
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handle_errors();
    
    ciphertext_len = len;
    
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handle_errors();
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
}

unsigned int decrypt(byte *ciphertext, unsigned int ciphertext_len, byte *key, byte *iv, byte *plaintext){
    EVP_CIPHER_CTX *ctx;
    
    unsigned int len;
    
    unsigned int plaintext_len;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handle_errors();
    
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_errors();
    
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handle_errors();
    plaintext_len = len;
    
    
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handle_errors();
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    return plaintext_len;
}

int create_hmac(byte *msg, unsigned int message_lenght, byte *val, EVP_PKEY *pkey){
    /* Returned to caller */
    int result = 0;
    EVP_MD_CTX* ctx = NULL;
    size_t req = 0;
    int rc;
    
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        handle_errors();
    }
    
    rc = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    if (rc != 1) {
        handle_errors();
    }
    
    rc = EVP_DigestSignUpdate(ctx, msg, message_lenght);
    if (rc != 1) {
        handle_errors();
    }
    
    rc = EVP_DigestSignFinal(ctx, NULL, &req);
    if (rc != 1) {
        handle_errors();
    }
    
    size_t vlen = 0;
    rc = EVP_DigestSignFinal(ctx, val, &vlen);
    if (rc != 1) {
        handle_errors();
    }
    
    result = 1;
    
    EVP_MD_CTX_free(ctx);
    
    return result;
}

int verify_hmac(byte *msg, unsigned int message_lenght, byte *val, EVP_PKEY *pkey){
    /* Returned to caller */
    int result = 0;
    EVP_MD_CTX* ctx = NULL;
    byte buff[32];
    size_t size;
    int rc;
    
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        handle_errors();
    }
    
    rc = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    if (rc != 1) {
        handle_errors();
    }
    
    rc = EVP_DigestSignUpdate(ctx, msg, message_lenght);
    if (rc != 1) {
        handle_errors();
    }
    
    size = sizeof(buff);
    rc = EVP_DigestSignFinal(ctx, buff, &size);
    if (rc != 1) {
        handle_errors();
    }
    
    result = (32 == size) && (CRYPTO_memcmp(val, buff, size) == 0);
    
    EVP_MD_CTX_free(ctx);
    return result;
}

int random_iv(byte* iv){
    return RAND_bytes(iv, 16);
}

int random_salt(byte* salt){
    return RAND_bytes(salt, 16);
}

void derive(byte* input, unsigned int input_lenght, byte* salt, byte* output, unsigned int iter){
    PKCS5_PBKDF2_HMAC(input, input_lenght, salt, 16, iter, DERIVE_FUNCTION, 32, output);
}

void derive_master_key(byte* password, unsigned int password_lenght, byte* salt, byte* master_key){
    derive(password, password_lenght, salt, master_key, N_ITERATIONS_MASTER);
}

void derive_child_key(byte* master_key, byte* salt, byte* child_key){
    derive(master_key, 32, salt, child_key, N_ITERATIONS_CHILD);
}

void get_keys(byte* master_key, key_group* keys){
    derive_child_key(master_key, salt_enc_key, keys->enc_key);
    derive_child_key(master_key, salt_mac_key, keys->mac_key);
}

int verify_key(byte* master_key, byte* token){
    byte digest[32];
    
    generate_token(master_key, digest);
    
    return CRYPTO_memcmp(digest, token, 32);
}

void generate_token(byte* master_key, byte* token){
    derive(master_key, 32, salt_token, token ,N_ITERATIONS_TOKEN);
}
