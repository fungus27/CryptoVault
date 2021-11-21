#include <string.h>

#include "data.h"



void initialize_data(login_data* data){
    data->pair_count = 0;
    data->login_pairs = NULL;
    memset(data->key_token, 0, 32);
    memset(data->path, 0, PATH_LIMIT);
}

void destroy_data(login_data* data){
    for (unsigned int i = 0; i < data->pair_count; i++)
    {
        free(data->login_pairs[i].login);
        free(data->login_pairs[i].password);
    }
    if(data->login_pairs)
        free(data->login_pairs);
}

// returns false if decryption fails
int load_data(login_data* data, key_group* keys){
    FILE* fp;
    fp = fopen(data->path, "rb");
    
    unsigned short ciphertext_block_count;
    fread(&(ciphertext_block_count), 2, 1, fp);
    
    if(!ciphertext_block_count)
        return 0;
    
    byte ciphertext[ciphertext_block_count * 16];
    byte main_iv[16];
    byte mac[32];
    byte message[ciphertext_block_count * 16 + 16];
    byte* cleartext = (byte*)malloc(ciphertext_block_count * 16);
    fread(ciphertext, ciphertext_block_count * 16, 1, fp);
    fread(main_iv, 16, 1, fp);
    fread(mac, 32, 1, fp);
    
    memcpy(message, ciphertext, ciphertext_block_count * 16);
    memcpy(message + ciphertext_block_count * 16, main_iv, 16);
    
    EVP_PKEY* mac_pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, keys->mac_key, 32);
    if(!verify_hmac(message, ciphertext_block_count * 16 + 16, mac, mac_pkey)){
        fclose(fp);
        free(cleartext);
        return 0;
    }
    EVP_PKEY_free(mac_pkey);
    
    decrypt(ciphertext, ciphertext_block_count * 16, keys->enc_key, main_iv, cleartext);
    
    byte* current_pointer = cleartext;
    memcpy(&(data->pair_count), current_pointer, 4);
    current_pointer += 4;
    
    // TODO(fungus): add metadata
    // time (4 bytes) number of iv generations (4 bytes) something else (8 bytes)
    current_pointer += 4 + 4 + 8;
    
    data->login_pairs = (login_pair*)malloc(sizeof(login_pair) * data->pair_count);
    for (unsigned int i = 0; i < data->pair_count; i++)
    {
        unsigned int login_size;
        unsigned short password_block_count; // 128-bit blocks (16 byte)
        
        memcpy(&login_size, current_pointer, 4);
        
        current_pointer += 4;
        memcpy(&password_block_count, current_pointer, 2);
        current_pointer += 2;
        
        data->login_pairs[i].login_size = login_size;
        data->login_pairs[i].password_block_count = password_block_count;
        data->login_pairs[i].login = (byte*)malloc(login_size);
        data->login_pairs[i].password = (byte*)malloc(password_block_count * 16);
        
        
        memcpy(data->login_pairs[i].login, current_pointer, login_size);
        current_pointer += login_size;
        
    }
    
    for (int i = 0; i < data->pair_count; i++)
    {
        memcpy(data->login_pairs[i].password, current_pointer, data->login_pairs[i].password_block_count * 16);
        current_pointer += data->login_pairs[i].password_block_count * 16;
        memcpy(data->login_pairs[i].password_iv, current_pointer, 16);
        current_pointer += 16;
    }
    
    fclose(fp);
    free(cleartext);
    return 1;
}

void save_data(login_data* data, key_group* keys){
    FILE* file_ptr;
    file_ptr = fopen(data->path, "wb");
    
    // TODO(fungus): add metadata
    // time (4 bytes) number of iv generations (4 bytes) something else (8 bytes)
    unsigned int cleartext_size = sizeof(data->pair_count) + 4 + 4 + 8;
    for (int i = 0; i < data->pair_count; i++)
    {
        cleartext_size += sizeof(unsigned int) + sizeof(unsigned short) + data->login_pairs[i].login_size + data->login_pairs[i].password_block_count * 16 + 16;
    }
    byte ciphertext[((cleartext_size + 15) / 16) * 16 + 16];
    byte* cleartext_to_encrypt = (byte*)malloc(cleartext_size);
    byte* current_pointer = cleartext_to_encrypt;
    
    memcpy(current_pointer, &(data->pair_count), 4);
    current_pointer += 4;
    
    current_pointer += 4 + 4 + 8;
    
    for (unsigned int i = 0; i < data->pair_count; i++)
    {
        memcpy(current_pointer, &(data->login_pairs[i].login_size), 4);
        current_pointer += 4;
        memcpy(current_pointer, &(data->login_pairs[i].password_block_count), 2);
        current_pointer += 2;
        memcpy(current_pointer, data->login_pairs[i].login, data->login_pairs[i].login_size);
        current_pointer += data->login_pairs[i].login_size;
    }
    
    for (int i = 0; i < data->pair_count; i++)
    {
        memcpy(current_pointer, data->login_pairs[i].password, data->login_pairs[i].password_block_count * 16);
        current_pointer += data->login_pairs[i].password_block_count * 16;
        memcpy(current_pointer, data->login_pairs[i].password_iv, 16);
        current_pointer += 16;
    }
    
    byte iv[16];
    byte mac[32] = {0};
    random_iv(iv);
    
    unsigned short ciphertext_block_count = encrypt(cleartext_to_encrypt, cleartext_size, keys->enc_key, iv, ciphertext) / 16;
    
    byte message[ciphertext_block_count * 16 + 16];
    memcpy(message, ciphertext, ciphertext_block_count * 16);
    memcpy(message + ciphertext_block_count * 16, iv, 16);
    
    EVP_PKEY* mac_pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, keys->mac_key, 32);
    create_hmac(message, ciphertext_block_count * 16 + 16, mac, mac_pkey);
    EVP_PKEY_free(mac_pkey);
    
    fwrite(&ciphertext_block_count, 2, 1, file_ptr);
    fwrite(ciphertext, ciphertext_block_count * 16, 1, file_ptr);
    fwrite(iv, 16, 1, file_ptr);
    fwrite(mac, 32, 1 , file_ptr);
    
    fclose(file_ptr);
    free(cleartext_to_encrypt);
}

void add_entry(login_data* data, key_group* keys, byte* login, unsigned int login_size, byte* password, unsigned int password_size){
    byte* encryptedPassword;
    byte iv[16];
    unsigned short password_block_count = (password_size + 15) / 16;
    
    random_iv(iv);
    
    encryptedPassword = (byte*)malloc(password_block_count * 16);
    password_block_count = encrypt(password, password_size, keys->enc_key, iv, encryptedPassword) / 16;
    
    data->login_pairs = (login_pair*)realloc(data->login_pairs, (data->pair_count + 1) * sizeof(login_pair));
    
    data->login_pairs[data->pair_count].login_size = login_size;
    data->login_pairs[data->pair_count].password_block_count = password_block_count;
    
    memcpy(data->login_pairs[data->pair_count].password_iv, iv, 16);
    
    data->login_pairs[data->pair_count].login = login;
    data->login_pairs[data->pair_count].password = encryptedPassword;
    (data->pair_count)++;
    
    save_data(data, keys);
}

void remove_entry(login_data* data, unsigned int index, key_group* keys){
    free(data->login_pairs[index].login);
    free(data->login_pairs[index].password);
    
    for (unsigned int i = index + 1; i < data->pair_count; i++)
    {
        data->login_pairs[i - 1] = data->login_pairs[i];
    }
    data->login_pairs = (login_pair*)realloc(data->login_pairs, (data->pair_count - 1) * sizeof(login_pair));
    data->pair_count--;
    
    save_data(data, keys);
}

void decrypt_entry(login_data* data, unsigned int index, key_group* keys, byte* password){
    decrypt(data->login_pairs[index].password, data->login_pairs[index].password_block_count * 16, keys->enc_key, data->login_pairs[index].password_iv, password);
}

void change_entry_login(login_data* data, unsigned int index, key_group* keys, byte* new_login, unsigned int new_login_size){
    free(data->login_pairs[index].login);
    
    data->login_pairs[index].login = new_login;
    data->login_pairs[index].login_size = new_login_size;
    
    save_data(data, keys);
}

void change_entry_password(login_data* data, unsigned int index, key_group* keys, byte* new_password, unsigned int new_password_size){
    unsigned short password_block_count = (new_password_size + 15) / 16;
    byte iv[16];
    byte* encryptedPassword;
    
    random_iv(iv);
    
    encryptedPassword = (byte*)malloc(password_block_count * 16);
    password_block_count = encrypt(new_password, new_password_size, keys, iv, encryptedPassword) / 16;
    
    free(data->login_pairs[index].password);
    data->login_pairs[index].password = encryptedPassword;
    data->login_pairs[index].password_block_count = password_block_count;
    
    memcpy(data->login_pairs[data->pair_count].password_iv, iv, 16);
    
    save_data(data, keys);
}

void change_vault_password(login_data* data, key_group* old_keys, key_group* new_keys){
    for (int i = 0; i < data->pair_count; i += 1){
        byte password[data->login_pairs[i].password_block_count * 16];
        decrypt(data->login_pairs[i].password, data->login_pairs[i].password_block_count * 16, old_keys->enc_key, data->login_pairs[i].password_iv, password);
        
        byte iv[16];
        byte* encryptedPassword;
        unsigned short password_block_count;
        {
            unsigned int password_size = strlen(password) + 1;
            password_block_count = (password_size + 15) / 16;
            
            random_iv(iv);
            
            encryptedPassword = (byte*)malloc(password_block_count * 16);
            password_block_count = encrypt(password, password_size, new_keys->enc_key, iv, encryptedPassword) / 16;
        }
        
        free(data->login_pairs[i].password);
        data->login_pairs[i].password = encryptedPassword;
        data->login_pairs[i].password_block_count = password_block_count;
        memcpy(data->login_pairs[i].password_iv, iv, 16);
    }
    
    save_data(data, new_keys);
}