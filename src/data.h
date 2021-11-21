#ifndef DATA_H
#define DATA_H

#include <openssl/evp.h>

#include "global_types.h"
#include "crypto.h"

// TODO(fungus): move to input file
#define PATH_LIMIT 260
#define INPUT_LIMIT 2048

typedef struct {
    unsigned int login_size;
    unsigned short password_block_count;
    byte* login;
    byte* password;
    byte password_iv[16];
} login_pair;

typedef struct {
    char path[PATH_LIMIT];
    unsigned int pair_count;
    login_pair* login_pairs;
    byte key_token[EVP_MAX_MD_SIZE];
} login_data;



void initialize_data(login_data* data);
void destroy_data(login_data* data);

int load_data(login_data* data, key_group* keys);
void save_data(login_data* data, key_group* keys);

void add_entry(login_data* data, key_group* keys, byte* login, unsigned int login_size, byte* password, unsigned int password_size);
void remove_entry(login_data* data, unsigned int index, key_group* keys);
void decrypt_entry(login_data* data, unsigned int index, key_group* keys, byte* password);

void change_entry_login(login_data* data, unsigned int index, key_group* keys, byte* new_login, unsigned int new_login_size);
void change_entry_password(login_data* data, unsigned int index, key_group* keys, byte* new_password, unsigned int new_password_size);

void change_vault_password(login_data* data, key_group* old_keys, key_group* new_keys);

#endif //DATA_H
