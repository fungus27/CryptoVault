#include <string.h>
#include <openssl/evp.h>

#include "data.h"

#include "crypto.h"

void initialize_data(login_data *data){
    data->pair_count = 0;
    data->login_pairs = NULL;
    memset(data->key_token, 0, 32);
    memset(data->path, 0, PATH_LIMIT);
    memset(data->master_salt, 0, 16);
}

void destroy_data(login_data *data){
    for (u32 i = 0; i < data->pair_count; i++)
    {
        free(data->login_pairs[i].login);
        free(data->login_pairs[i].password);
    }
    if(data->login_pairs)
        free(data->login_pairs);
}

void load_master_salt(login_data *data){
    FILE *fp;
    fp = fopen(data->path, "rb");
    
    fread(data->master_salt, 16, 1, fp);
    
    fclose(fp);
}

// returns false if decryption fails
i32 load_data(login_data *data, key_group *keys){
    FILE *fp;
    fp = fopen(data->path, "rb");
    
    fseek(fp, 0, SEEK_END);
    u32 ciphertext_size = ftell(fp) - 64;/* master_salt + iv + mac */
    rewind(fp);
    
    fread(data->master_salt, 16, 1, fp);
    
    byte ciphertext[ciphertext_size];
    byte iv[16];
    byte mac[32];
    
    fread(ciphertext, ciphertext_size, 1, fp);
    fread(iv, 16, 1, fp);
    fread(mac, 32, 1, fp);
    
    byte auth_message[ciphertext_size + 32];
    memcpy(auth_message, data->master_salt, 16);
    memcpy(auth_message + 16, ciphertext, ciphertext_size);
    memcpy(auth_message + ciphertext_size + 16, iv, 16);
    
    EVP_PKEY *mac_pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, keys->mac_key, 32);
    if(!verify_hmac(auth_message, ciphertext_size + 16 + 16, mac, mac_pkey)){
        fclose(fp);
        return 0;
    }
    EVP_PKEY_free(mac_pkey);
    
    byte *cleartext = malloc(ciphertext_size);
    decrypt(ciphertext, ciphertext_size, keys->enc_key, iv, cleartext);
    
    byte *current_pointer = cleartext;
    memcpy(&(data->pair_count), current_pointer, 4);
    current_pointer += 4;
    
    // TODO(fungus): add metadata
    // time (4 bytes) number of iv generations (4 bytes) something else (8 bytes)
    current_pointer += 4 + 4 + 8;
    
    data->login_pairs = malloc(sizeof(login_pair) * data->pair_count);
    for (u32 i = 0; i < data->pair_count; i++)
    {
        u32 login_size;
        u32 enc_password_size; // 128-bit blocks (16 byte)
        
        memcpy(&login_size, current_pointer, 4);
        current_pointer += 4;
        
        memcpy(&enc_password_size, current_pointer, 4);
        current_pointer += 4;
        
        data->login_pairs[i].login_size = login_size;
        data->login_pairs[i].enc_password_size = enc_password_size;
        data->login_pairs[i].login = malloc(login_size);
        data->login_pairs[i].password = malloc(enc_password_size);
        
        memcpy(data->login_pairs[i].login, current_pointer, login_size);
        current_pointer += login_size;
    }
    
    for (i32 i = 0; i < data->pair_count; i++)
    {
        memcpy(data->login_pairs[i].password, current_pointer, data->login_pairs[i].enc_password_size);
        current_pointer += data->login_pairs[i].enc_password_size;
        
        memcpy(data->login_pairs[i].password_iv, current_pointer, 16);
        current_pointer += 16;
    }
    
    fclose(fp);
    free(cleartext);
    return 1;
}

void save_data(login_data *data, key_group *keys){
    FILE *file_ptr;
    file_ptr = fopen(data->path, "wb");
    
    // TODO(fungus): add metadata
    // time (4 bytes) number of iv generations (4 bytes) something else (8 bytes)
    u32 cleartext_size = sizeof(data->pair_count) + 4 + 4 + 8;
    for (i32 i = 0; i < data->pair_count; i++)
    {
        cleartext_size += sizeof(data->login_pairs[i].login_size) + sizeof(data->login_pairs[i].enc_password_size) + data->login_pairs[i].login_size + data->login_pairs[i].enc_password_size + 16;
    }
    
    byte ciphertext[CEIL_TO_NEAREST(cleartext_size, 16) + 16];
    byte *cleartext_to_encrypt = malloc(cleartext_size);
    byte *current_pointer = cleartext_to_encrypt;
    
    memcpy(current_pointer, &(data->pair_count), 4);
    current_pointer += 4;
    
    current_pointer += 4 + 4 + 8;
    
    for (u32 i = 0; i < data->pair_count; i++)
    {
        memcpy(current_pointer, &(data->login_pairs[i].login_size), 4);
        current_pointer += 4;
        
        memcpy(current_pointer, &(data->login_pairs[i].enc_password_size), 4);
        current_pointer += 4;
        
        memcpy(current_pointer, data->login_pairs[i].login, data->login_pairs[i].login_size);
        current_pointer += data->login_pairs[i].login_size;
    }
    
    for (u32 i = 0; i < data->pair_count; i++)
    {
        memcpy(current_pointer, data->login_pairs[i].password, data->login_pairs[i].enc_password_size);
        current_pointer += data->login_pairs[i].enc_password_size;
        
        memcpy(current_pointer, data->login_pairs[i].password_iv, 16);
        current_pointer += 16;
    }
    
    byte iv[16];
    random_iv(iv);
    
    u32 ciphertext_size = encrypt(cleartext_to_encrypt, cleartext_size, keys->enc_key, iv, ciphertext);
    
    byte auth_message[ciphertext_size + 32];
    memcpy(auth_message, data->master_salt, 16);
    memcpy(auth_message + 16 , ciphertext, ciphertext_size);
    memcpy(auth_message + ciphertext_size + 16, iv, 16);
    
    byte mac[32];
    EVP_PKEY *mac_pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, keys->mac_key, 32);
    create_hmac(auth_message, ciphertext_size + 32, mac, mac_pkey);
    EVP_PKEY_free(mac_pkey);
    
    fwrite(data->master_salt, 16, 1, file_ptr);
    fwrite(ciphertext, ciphertext_size, 1, file_ptr);
    fwrite(iv, 16, 1, file_ptr);
    
    fwrite(mac, 32, 1 , file_ptr);
    
    fclose(file_ptr);
    free(cleartext_to_encrypt);
}

void add_entry(login_data *data, key_group *keys, byte *login, u32 login_size, byte *password, u32 password_size){
    byte *encrypted_password;
    byte iv[16];
    
    random_iv(iv);
    
    encrypted_password = malloc(CEIL_TO_NEAREST(password_size, 16) + 16);
    u32 enc_password_size = encrypt(password, password_size, keys->enc_key, iv, encrypted_password);
    
    data->login_pairs = (login_pair*)realloc(data->login_pairs, (data->pair_count + 1) * sizeof(login_pair));
    
    data->login_pairs[data->pair_count].login_size = login_size;
    data->login_pairs[data->pair_count].enc_password_size = enc_password_size;
    
    memcpy(data->login_pairs[data->pair_count].password_iv, iv, 16);
    
    data->login_pairs[data->pair_count].login = login;
    data->login_pairs[data->pair_count].password = encrypted_password;
    (data->pair_count)++;
    
    save_data(data, keys);
}

void remove_entry(login_data *data, u32 index, key_group *keys){
    free(data->login_pairs[index].login);
    free(data->login_pairs[index].password);
    
    for (u32 i = index + 1; i < data->pair_count; i++)
    {
        data->login_pairs[i - 1] = data->login_pairs[i];
    }
    data->login_pairs = (login_pair*)realloc(data->login_pairs, (data->pair_count - 1) * sizeof(login_pair));
    data->pair_count--;
    
    save_data(data, keys);
}

void decrypt_entry(login_data *data, u32 index, key_group *keys, byte *password){
    decrypt(data->login_pairs[index].password, data->login_pairs[index].enc_password_size, keys->enc_key, data->login_pairs[index].password_iv, password);
}

void change_entry_login(login_data *data, u32 index, key_group *keys, byte *new_login, u32 new_login_size){
    free(data->login_pairs[index].login);
    
    data->login_pairs[index].login = new_login;
    data->login_pairs[index].login_size = new_login_size;
    
    save_data(data, keys);
}

void change_entry_password(login_data *data, u32 index, key_group *keys, byte *new_password, u32 new_password_size){
    byte iv[16];
    byte *encrypted_password;
    
    random_iv(iv);
    
    encrypted_password = malloc(CEIL_TO_NEAREST(new_password_size, 16) + 16);
    u32 enc_password_size = encrypt(new_password, new_password_size, keys, iv, encrypted_password);
    
    free(data->login_pairs[index].password);
    data->login_pairs[index].password = encrypted_password;
    data->login_pairs[index].enc_password_size = enc_password_size;
    
    memcpy(data->login_pairs[data->pair_count].password_iv, iv, 16);
    
    save_data(data, keys);
}

void change_vault_password(login_data *data, key_group *old_keys, key_group *new_keys){
    for (u32 i = 0; i < data->pair_count; i += 1){
        byte password[data->login_pairs[i].enc_password_size];
        decrypt(data->login_pairs[i].password, data->login_pairs[i].enc_password_size, old_keys->enc_key, data->login_pairs[i].password_iv, password);
        
        byte iv[16];
        byte *encrypted_password;
        
        u32 password_size = strlen(password) + 1;
        u32 enc_password_size = CEIL_TO_NEAREST(password_size, 16) + 16;
        
        random_iv(iv);
        
        encrypted_password = malloc(enc_password_size);
        enc_password_size = encrypt(password, password_size, new_keys->enc_key, iv, encrypted_password);
        
        free(data->login_pairs[i].password);
        data->login_pairs[i].password = encrypted_password;
        data->login_pairs[i].enc_password_size = enc_password_size;
        memcpy(data->login_pairs[i].password_iv, iv, 16);
    }
    
    save_data(data, new_keys);
}