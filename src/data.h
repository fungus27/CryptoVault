#ifndef DATA_H
#define DATA_H

#include <openssl/evp.h>

#include "global_types.h"
#include "crypto.h"

typedef struct {
    u32 login_size;
    u32 enc_password_size;
    byte* login;
    byte* password;
    byte password_iv[16];
} login_pair;

typedef struct {
    char path[PATH_LIMIT];
    u32 pair_count;
    login_pair* login_pairs;
    byte master_salt[16];
    byte key_token[EVP_MAX_MD_SIZE];
} login_data;

void initialize_data(login_data* data);
void destroy_data(login_data* data);

void load_master_salt(login_data* data);

i32 load_data(login_data* data, key_group* keys);
void save_data(login_data* data, key_group* keys);

void add_entry(login_data* data, key_group* keys, byte* login, u32 login_size, byte* password, u32 password_size);
void remove_entry(login_data* data, u32 index, key_group* keys);
void decrypt_entry(login_data* data, u32 index, key_group* keys, byte* password);

void change_entry_login(login_data* data, u32 index, key_group* keys, byte* new_login, u32 new_login_size);
void change_entry_password(login_data* data, u32 index, key_group* keys, byte* new_password, u32 new_password_size);

void change_vault_password(login_data* data, key_group* old_keys, key_group* new_keys);

#endif //DATA_H
