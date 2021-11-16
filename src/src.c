#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <math.h>
#include <limits.h>
#include <ncurses.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define _DEBUG

#ifdef _DEBUG
#define handle_errors() print_errors()
#else
#define handle_errors()
#endif

#define PATH_LIMIT 260
#define INPUT_LIMIT 2048

#define N_ITERATIONS_MASTER 300000
#define N_ITERATIONS_CHILD 10000



typedef unsigned char byte;

typedef struct{
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
    byte key_token[32];
} login_data;

typedef struct {
    byte key[32];
    byte m_key[32];
} master_key;

typedef struct {
    WINDOW* border;
    WINDOW* prompt;
} prompt_window;



static byte salt1[16] = {27 , 130, 103, 40, 138, 19, 43, 13, 2, 228, 45, 26, 242, 232, 131, 247};
static byte salt2[16] = {50 , 156, 173, 242, 26, 90, 239, 246, 139, 216, 70, 53, 254, 1, 198, 43};
static byte salt3[16] = {38, 201, 151, 231, 208, 219, 244, 17, 111, 186, 53, 122, 21, 239, 173, 155};



unsigned int max(unsigned int a, unsigned int b){
    return a > b ? a : b;
}

unsigned int min(unsigned int a, unsigned int b){
    return a < b ? a : b;
}

void print_errors(void)
{
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



unsigned int encrypt(byte *plaintext, unsigned int plaintext_len, byte *key, byte *iv, byte *ciphertext)
{
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

unsigned int decrypt(byte *ciphertext, unsigned int ciphertext_len, byte *key,byte *iv, byte *plaintext)
{
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

int create_hmac(byte *msg, unsigned int message_lenght, byte *val, EVP_PKEY *pkey)
{
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

int verify_hmac(byte *msg, unsigned int message_lenght, byte *val, EVP_PKEY *pkey)
{
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

void derive_key(byte* password, unsigned int password_lenght, byte* salt, byte* key, unsigned int iter){
    PKCS5_PBKDF2_HMAC(password, password_lenght, salt, 16, iter, EVP_sha256(), 32, key);
}

void hash_sha256(byte* message, unsigned int message_lenght, byte* digest){
    EVP_MD_CTX *mdctx;
    
	if((mdctx = EVP_MD_CTX_new()) == NULL)
		handle_errors();
    
	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handle_errors();
    
	if(1 != EVP_DigestUpdate(mdctx, message, message_lenght))
		handle_errors();
    
	if(1 != EVP_DigestFinal_ex(mdctx, digest, NULL))
		handle_errors();
    
	EVP_MD_CTX_free(mdctx);
}

void generate_token(master_key* key, byte* token){
    byte concat[64];
    
    memcpy(concat, key->key, 32);
    memcpy(concat + 32, key->m_key, 32);
    
    hash_sha256(concat, 64, token);
}

// return 0 if verified
int verify_key(master_key* key, byte* token){
    byte digest[32];
    
    generate_token(key, digest);
    
    return CRYPTO_memcmp(digest, token, 32);
}



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
int load_data(login_data* data, master_key* key){
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
    
    EVP_PKEY* m_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key->m_key, 32);
    if(!verify_hmac(message, ciphertext_block_count * 16 + 16, mac, m_key)){
        fclose(fp);
        free(cleartext);
        return 0;
    }
    EVP_PKEY_free(m_key);
    generate_token(key, data->key_token);
    
    decrypt(ciphertext, ciphertext_block_count * 16, key->key, main_iv, cleartext);
    
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

void save_data(login_data* data, master_key* key){
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
    
    unsigned short ciphertext_block_count = encrypt(cleartext_to_encrypt, cleartext_size, key->key, iv, ciphertext) / 16;
    
    byte message[ciphertext_block_count * 16 + 16];
    memcpy(message, ciphertext, ciphertext_block_count * 16);
    memcpy(message + ciphertext_block_count * 16, iv, 16);
    
    EVP_PKEY* m_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key->m_key, 32);
    create_hmac(message, ciphertext_block_count * 16 + 16, mac, m_key);
    EVP_PKEY_free(m_key);
    
    fwrite(&ciphertext_block_count, 2, 1, file_ptr);
    fwrite(ciphertext, ciphertext_block_count * 16, 1, file_ptr);
    fwrite(iv, 16, 1, file_ptr);
    fwrite(mac, 32, 1 , file_ptr);
    
    fclose(file_ptr);
    free(cleartext_to_encrypt);
}



void copy_to_clipboard(char* input){
    char command[INPUT_LIMIT];
    sprintf(command, "printf %s | xclip -sel clip", input);
    system(command);
}

int get_path(char* path, char* prompt, WINDOW* w_prompt){
    mvwprintw(w_prompt, 0, 0, prompt);
    
    wgetnstr(w_prompt, path, PATH_LIMIT);
    return access(path, F_OK);
}

// returns the size of the login WITH THE NULL TERMINATOR
unsigned int get_unique_login(login_data* data, byte* login, char* prompt, WINDOW* w_prompt){
    login_input:
    
    mvwprintw(w_prompt, 0, 0, prompt);
    wgetnstr(w_prompt, login, INPUT_LIMIT-1);
    
    unsigned int login_size = strlen(login) + 1;
    
    for (unsigned i = 0; i < data->pair_count; i++)
    {
        if(!strcmp(login, data->login_pairs[i].login)){
            mvwprintw(w_prompt, 1, 0, "Login already used.\n");
            wgetch(w_prompt);
            goto login_input;
        }   
    }
    
    return login_size;
}

// returns the size of the password WITH THE NULL TERMINATOR
unsigned int get_password(byte* password, char* prompt, WINDOW* w_prompt){
    mvwprintw(w_prompt, 0, 0, prompt);
    wgetnstr(w_prompt, password, INPUT_LIMIT-1);
    unsigned int password_size = strlen(password) + 1;
    
    return password_size;
}

void random_password(unsigned int password_size, byte* password){
    unsigned int raw_password_size = (unsigned int)ceilf((float)(password_size - 1) * 0.75f);
    
    byte raw_password[raw_password_size];
    
    RAND_bytes(raw_password, raw_password_size);
    
    byte password_buffer[INPUT_LIMIT];
    
    EVP_EncodeBlock(password_buffer, raw_password, raw_password_size);
    memcpy(password, password_buffer, password_size - 1);
    password[password_size - 1] = 0;
}

unsigned int get_uint(char* prompt, WINDOW* w_prompt){
    char input[INPUT_LIMIT];
    
    mvwprintw(w_prompt, 0, 0, prompt);
    wgetnstr(w_prompt, input, INPUT_LIMIT-1);
    
    return (unsigned int)min(strtoul(input, NULL, 10), UINT_MAX);
}

void get_key(master_key* key, char* prompt, WINDOW* w_prompt){
    byte password[INPUT_LIMIT];
    byte master_key[32];
    mvwprintw(w_prompt, 0, 0, prompt);
    
    wgetnstr(w_prompt, password, INPUT_LIMIT-1);
    
    derive_key(password, -1, salt1, master_key, N_ITERATIONS_MASTER);
    derive_key(master_key, 32, salt2, key->key, N_ITERATIONS_CHILD);
    derive_key(master_key, 32, salt3, key->m_key, N_ITERATIONS_CHILD);
}



void add_entry(login_data* data, master_key* key, byte* login, unsigned int login_size, byte* password, unsigned int password_size){
    byte* encryptedPassword;
    byte iv[16];
    unsigned short password_block_count = (password_size + 15) / 16;
    
    random_iv(iv);
    
    encryptedPassword = (byte*)malloc(password_block_count * 16);
    password_block_count = encrypt(password, password_size, key->key, iv, encryptedPassword) / 16;
    
    data->login_pairs = (login_pair*)realloc(data->login_pairs, (data->pair_count + 1) * sizeof(login_pair));
    
    data->login_pairs[data->pair_count].login_size = login_size;
    data->login_pairs[data->pair_count].password_block_count = password_block_count;
    
    memcpy(data->login_pairs[data->pair_count].password_iv, iv, 16);
    
    data->login_pairs[data->pair_count].login = login;
    data->login_pairs[data->pair_count].password = encryptedPassword;
    (data->pair_count)++;
    
    save_data(data, key);
}

void remove_entry(login_data* data, unsigned int index, master_key* key){
    free(data->login_pairs[index].login);
    free(data->login_pairs[index].password);
    
    for (unsigned int i = index + 1; i < data->pair_count; i++)
    {
        data->login_pairs[i - 1] = data->login_pairs[i];
    }
    data->login_pairs = (login_pair*)realloc(data->login_pairs, (data->pair_count - 1) * sizeof(login_pair));
    data->pair_count--;
    
    save_data(data, key);
}

void decrypt_entry(login_data* data, unsigned int index, master_key* key, byte* password){
    decrypt(data->login_pairs[index].password, data->login_pairs[index].password_block_count * 16, key->key, data->login_pairs[index].password_iv, password);
}

void change_entry_login(login_data* data, unsigned int index, master_key* key, byte* new_login, unsigned int new_login_size){
    free(data->login_pairs[index].login);
    
    data->login_pairs[index].login = new_login;
    data->login_pairs[index].login_size = new_login_size;
    
    save_data(data, key);
}

void change_entry_password(login_data* data, unsigned int index, master_key* key, byte* new_password, unsigned int new_password_size){
    unsigned short password_block_count = (new_password_size + 15) / 16;
    byte iv[16];
    byte* encryptedPassword;
    
    random_iv(iv);
    
    encryptedPassword = (byte*)malloc(password_block_count * 16);
    password_block_count = encrypt(new_password, new_password_size, key->key, iv, encryptedPassword) / 16;
    
    free(data->login_pairs[index].password);
    data->login_pairs[index].password = encryptedPassword;
    data->login_pairs[index].password_block_count = password_block_count;
    
    memcpy(data->login_pairs[data->pair_count].password_iv, iv, 16);
    
    save_data(data, key);
}

void change_vault_password(login_data* data, master_key* key, master_key* new_key){
    for (int i = 0; i < data->pair_count; i += 1){
        byte password[data->login_pairs[i].password_block_count * 16];
        decrypt(data->login_pairs[i].password, data->login_pairs[i].password_block_count * 16, key->key, data->login_pairs[i].password_iv, password);
        
        byte iv[16];
        byte* encryptedPassword;
        unsigned short password_block_count;
        {
            unsigned int password_size = strlen(password) + 1;
            password_block_count = (password_size + 15) / 16;
            
            random_iv(iv);
            
            encryptedPassword = (byte*)malloc(password_block_count * 16);
            password_block_count = encrypt(password, password_size, new_key->key, iv, encryptedPassword) / 16;
        }
        
        free(data->login_pairs[i].password);
        data->login_pairs[i].password = encryptedPassword;
        data->login_pairs[i].password_block_count = password_block_count;
        memcpy(data->login_pairs[i].password_iv, iv, 16);
    }
    
    save_data(data, new_key);
}



unsigned int create_menu(int height, int width, int y, int x, char** options, unsigned int options_count, unsigned int start_option){
    int curs_vis = curs_set(0);
    
    WINDOW* menu_border = newwin(height + 2, width + 4, y - 1, x - 2);
    WINDOW* menu = derwin(menu_border, height, width, 1, 2);
    
    keypad(menu, true);
    
    box(menu_border, 0, 0);
    wrefresh(menu_border);
    
    unsigned int selected = start_option;
    
    while(1){
        for (unsigned int i = 0; i < options_count; i++)
        {   
            if(i == selected)
                wattron(menu, A_STANDOUT);
            
            mvwprintw(menu, i, 0, "%-*s", width, options[i]);
            
            wattroff(menu, A_STANDOUT);
        }
        
        touchwin(menu_border);
        int input = wgetch(menu);
        
        if(input == KEY_UP && selected > 0)
            selected--;
        else if(input == KEY_DOWN && selected < options_count - 1)
            selected++;
        else if(input == 10){
            delwin(menu);
            delwin(menu_border);
            curs_set(curs_vis);
            return selected;
        }
    }
}


unsigned int yes_no_prompt(char* prompt, WINDOW* w_prompt){
    noecho();
    
    wclear(w_prompt);
    mvwprintw(w_prompt, 0, 0, prompt);
    
    int ans = 0;
    do
    {
        ans = wgetch(w_prompt);
        
    } while(ans != 'y' && ans != 'Y' && ans != 'n' && ans != 'N');
    
    wclear(w_prompt);
    wrefresh(w_prompt);
    
    echo();
    
    return ans == 'y' || ans == 'Y' ? 1 : 0;
}

int main(){
    initialize();
    initscr();
    getch(); // 4coder
    cbreak();
    
    if(has_colors()){
        start_color();
        use_default_colors();
    }
    
    // TODO(fungus): make better inputs, add third key for password encryption, make a 30s clipboard reset, add file encryption, test, add comments, clean up code etc.
    
    int height, width;
    getmaxyx(stdscr, height, width);
    
    login_data data;
    initialize_data(&data);
    
    prompt_window w_prompt;
    w_prompt.border = newwin(height/3, width, 0, 0);
    w_prompt.prompt = derwin(w_prompt.border, height/3 - 2, width - 4, 1, 2);
    
    box(w_prompt.border, 0, 0);
    wrefresh(w_prompt.border);
    
    first_menu:
    
    char * first_options[] = {"Create password bank", "Open password bank", "Exit"};
    unsigned int first_option = create_menu(3, 30, height/2-3 , width/2-17, first_options, 3, 0);
    
    if(first_option == 2){
        endwin();
        return 0;
    }
    
    if(!first_option){
        vault_create:
        if(!get_path(data.path, "Enter new vault path and name: ", w_prompt.prompt)){
            unsigned int ans = yes_no_prompt("File already exists. Do you want to override? (y/n)", w_prompt.prompt);
            if(!ans)
                goto first_menu;
        }
        {
            char vault_prompt[INPUT_LIMIT];
            
            sprintf(vault_prompt, "Do you want to create a new vault at: \"%s\"? (y/n)", data.path);
            
            unsigned int ans = yes_no_prompt(vault_prompt, w_prompt.prompt);
            if(!ans)
                goto first_menu;
            
            master_key key;
            
            get_key(&key, "Enter new vault password: ", w_prompt.prompt);
            
            wclear(w_prompt.prompt);
            wrefresh(w_prompt.prompt);
            
            generate_token(&key, data.key_token);
            
            save_data(&data, &key);
        }
    }
    else {
        if(get_path(data.path, "Enter vault path: ", w_prompt.prompt)){
            unsigned int ans = yes_no_prompt("File does not exist. Do you want to create a new one? (y/n)", w_prompt.prompt);
            if(ans)
                goto vault_create;
            else
                goto first_menu;
        }
        
        wclear(w_prompt.prompt);
        
        pass:
        {
            master_key key;
            get_key(&key, "Enter vault password: ", w_prompt.prompt);
            
            wclear(w_prompt.prompt);
            wrefresh(w_prompt.prompt);
            
            if(!load_data(&data, &key)){
                unsigned int ans = yes_no_prompt("Invalid password. Do you want to try again? (y/n)", w_prompt.prompt);
                if(ans)
                    goto pass;
                goto first_menu;
            }
        }
    }
    
    clear();
    refresh();
    box(w_prompt.border, 0, 0);
    wrefresh(w_prompt.border);
    
    // TODO(fungus): move Change vault password to other menu
    const unsigned int extra_options_count = 5;
    char *extra_options[5] = {
        "Add entry",
        "Remove entry",
        "Change entry",
        "Change vault password",
        "Exit"
    };
    
    char **options = (char**)malloc(sizeof(char*) * (data.pair_count+extra_options_count));
    for(int i = 0; i < data.pair_count; ++i){
        options[i] = data.login_pairs[i].login;
    }
    
    memcpy(&options[data.pair_count], extra_options, extra_options_count * sizeof(char*));
    
    unsigned int last_option = 0;
    
    while(1){
        last_option = create_menu(data.pair_count+extra_options_count, width/2,
                                  height/2-(data.pair_count+3)/2 , width/2-(width/4),
                                  options, data.pair_count+extra_options_count, last_option);
        
        if(last_option < data.pair_count){ // Show entry
            pass_show:
            {
                wclear(w_prompt.prompt);
                
                master_key key;
                get_key(&key, "Enter vault password: ", w_prompt.prompt);
                
                if(!verify_key(&key, data.key_token)){
                    
                    wclear(w_prompt.prompt);
                    
                    byte password[data.login_pairs[last_option].password_block_count * 16];
                    decrypt_entry(&data, last_option, &key, password);
                    
                    copy_to_clipboard(password);
                    
                    mvwprintw(w_prompt.prompt, 0 ,0, "Password copied to clipboard.");
                    wrefresh(w_prompt.prompt);
                }
                else{
                    unsigned int ans = yes_no_prompt("Invalid password. Do you want to try again? (y/n)", w_prompt.prompt);
                    if(ans)
                        goto pass_show;
                }
            }
        }
        else if(last_option == data.pair_count){ // Add entry
            pass_add:
            {
                wclear(w_prompt.prompt);
                
                master_key key;
                get_key(&key, "Enter vault password: ", w_prompt.prompt);
                
                if(!verify_key(&key, data.key_token)){
                    wclear(w_prompt.prompt);
                    
                    byte* login = malloc(sizeof(byte) * INPUT_LIMIT); 
                    unsigned int login_size = get_unique_login(&data, login, "Enter new login: ", w_prompt.prompt);
                    login = realloc(login, login_size);
                    
                    wclear(w_prompt.prompt);
                    
                    byte password[INPUT_LIMIT];
                    unsigned int password_size;
                    
                    unsigned int generate = yes_no_prompt("Do you want to generate a strong password? (y/n)", w_prompt.prompt);
                    wclear(w_prompt.prompt);
                    
                    if(generate){
                        password_size = get_uint("Enter password lenght (recommended 16-64): ", w_prompt.prompt) + 1;
                        random_password(password_size, password);
                    }
                    else{
                        password_size = get_password(password, "Enter password: ", w_prompt.prompt);
                    }
                    
                    add_entry(&data, &key,  login, login_size, password, password_size);
                    
                    wclear(w_prompt.prompt);
                    wrefresh(w_prompt.prompt);
                }
                else{
                    unsigned int ans = yes_no_prompt("Invalid password. Do you want to try again? (y/n)", w_prompt.prompt);
                    if(ans)
                        goto pass_add;
                }
            }
            
            options = (char**)realloc(options, sizeof(char*) * (data.pair_count+extra_options_count));
            
            options[data.pair_count-1] = data.login_pairs[data.pair_count-1].login; 
            memcpy(&options[data.pair_count], extra_options, extra_options_count * sizeof(char*));
        }
        else if(last_option == data.pair_count+1){ // Remove entry
            pass_rem_enter:
            wclear(w_prompt.prompt);
            
            master_key key;
            get_key(&key, "Enter vault password: ", w_prompt.prompt);
            
            if(!verify_key(&key, data.key_token)){
                last_option = 0;
                
                pass_rem:
                char *rem_options[data.pair_count+1];
                for (int i = 0; i < data.pair_count; i += 1){
                    rem_options[i] = data.login_pairs[i].login;
                }
                
                rem_options[data.pair_count] = "Exit";
                
                wclear(w_prompt.prompt);
                mvwprintw(w_prompt.prompt, 0, 0, "Choose entry to remove...");
                wrefresh(w_prompt.prompt);
                
                clear();
                refresh();
                box(w_prompt.border, 0, 0);
                wrefresh(w_prompt.border);
                
                unsigned int to_remove = create_menu(data.pair_count+1, width/2, 
                                                     height/2-(data.pair_count+3)/2 , width/2-(width/4),
                                                     rem_options, data.pair_count+1, 0);
                
                if(to_remove == data.pair_count){
                    clear();
                    refresh();
                    box(w_prompt.border, 0, 0);
                    wrefresh(w_prompt.border);
                    wclear(w_prompt.prompt);
                    wrefresh(w_prompt.prompt);
                    continue;
                }
                else{
                    char remove_prompt[INPUT_LIMIT];
                    sprintf(remove_prompt, "Remove \"%s\"? (y/n)", data.login_pairs[to_remove].login);
                    
                    unsigned int ans = yes_no_prompt(remove_prompt, w_prompt.prompt);
                    if(!ans)
                        goto pass_rem;
                    
                    remove_entry(&data, to_remove, &key);
                    clear();
                    refresh();
                    box(w_prompt.border, 0, 0);
                    wrefresh(w_prompt.border);
                }
            }
            else{
                unsigned int ans = yes_no_prompt("Invalid password. Do you want to try again? (y/n)", w_prompt.prompt);
                if(ans)
                    goto pass_rem_enter;
            }
            
            options = (char**)realloc(options, sizeof(char*) * (data.pair_count+extra_options_count));
            for(int i = 0; i < data.pair_count; ++i){
                options[i] = data.login_pairs[i].login;
            }
            
            memcpy(&options[data.pair_count], extra_options, extra_options_count * sizeof(char*));
        }
        else if(last_option == data.pair_count+2){ // Change entry
            pass_change_enter:
            wclear(w_prompt.prompt);
            
            master_key key;
            get_key(&key, "Enter vault password: ", w_prompt.prompt);
            
            if(!verify_key(&key, data.key_token)){
                pass_change:
                char *change_options[data.pair_count+1];
                for (int i = 0; i < data.pair_count; i += 1){
                    change_options[i] = data.login_pairs[i].login;
                }
                
                change_options[data.pair_count] = "Exit";
                
                wclear(w_prompt.prompt);
                mvwprintw(w_prompt.prompt, 0, 0, "Choose entry to change...");
                wrefresh(w_prompt.prompt);
                
                clear();
                refresh();
                box(w_prompt.border, 0, 0);
                wrefresh(w_prompt.border);
                
                unsigned int to_change = create_menu(data.pair_count+1, width/2,
                                                     height/2-(data.pair_count+3)/2 , width/2-(width/4),
                                                     change_options, data.pair_count+1, 0);
                
                if(to_change == data.pair_count){
                    clear();
                    refresh();
                    box(w_prompt.border, 0, 0);
                    wrefresh(w_prompt.border);
                    wclear(w_prompt.prompt);
                    wrefresh(w_prompt.prompt);
                    continue;
                }
                else{
                    wclear(w_prompt.prompt);
                    
                    byte* new_login = malloc(sizeof(byte) * INPUT_LIMIT); 
                    unsigned int new_login_size = get_unique_login(&data, new_login, "New login (leave blank if not changing): ", w_prompt.prompt);
                    new_login = realloc(new_login, new_login_size);
                    
                    wclear(w_prompt.prompt);
                    
                    byte new_password[INPUT_LIMIT];
                    unsigned int new_password_size = get_password(new_password, "New password (leave blank if not changing): ", w_prompt.prompt);
                    
                    if(new_login_size - 1)
                        change_entry_login(&data, to_change, &key, new_login, new_login_size);
                    if(new_password_size - 1)
                        change_entry_password(&data, to_change, &key, new_password, new_password_size);
                    
                    options[to_change] = data.login_pairs[to_change].login;
                    
                    clear();
                    refresh();
                    box(w_prompt.border, 0, 0);
                    wrefresh(w_prompt.border);
                }
            }
            else{
                unsigned int ans = yes_no_prompt("Invalid password. Do you want to try again? (y/n)", w_prompt.prompt);
                if(ans)
                    goto pass_change_enter;
            }
        }
        else if(last_option == data.pair_count + 3){ // Change vault password
            v_pass_change_enter:
            wclear(w_prompt.prompt);
            
            master_key key;
            get_key(&key, "Enter old vault password: ", w_prompt.prompt);
            
            if(!verify_key(&key, data.key_token)){
                
                master_key new_key;
                
                wclear(w_prompt.prompt);
                get_key(&new_key, "Enter new vault password: ", w_prompt.prompt);
                
                unsigned int ans = yes_no_prompt("Are you sure you want to change the vault's password? (y/n)", w_prompt.prompt);
                
                if(ans){
                    generate_token(&new_key, data.key_token);
                    change_vault_password(&data, &key, &new_key);
                }
                else{
                    wclear(w_prompt.prompt);
                    continue;
                }
            }
            else{
                unsigned int ans = yes_no_prompt("Invalid password. Do you want to try again? (y/n)", w_prompt.prompt);
                if(ans)
                    goto v_pass_change_enter;
            }
        }
        else{ // Exit
            wclear(w_prompt.prompt);
            if(yes_no_prompt("Do you want to exit? (y/n)", w_prompt.prompt))
                break;
        }
    }
    
    free(options);
    
    destroy_data(&data);
    
    endwin();
    
    finalize();
}