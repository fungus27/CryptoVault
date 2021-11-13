#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <unistd.h>
#include <assert.h>
#include <math.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define _DEBUG


#ifdef _DEBUG
#define handleErrors() printErrors()
#else
#define handleErrors()
#endif

#define PATH_LIMIT 260
#define INPUT_LIMIT 2048

#define N_ITERATIONS_MASTER 300000
#define N_ITERATIONS_CHILD 10000

typedef unsigned char BYTE;

typedef struct{
    unsigned int login_size;
    unsigned short password_block_count;
    BYTE* login;
    BYTE* password;
    BYTE password_iv[16];
} LoginPair;

typedef struct {
    char path[PATH_LIMIT];
    unsigned int pair_count;
    LoginPair* loginPairs;
    BYTE key_token[32];
} LoginData;

typedef struct {
    BYTE key[32];
    BYTE m_key[32];
} Key;

typedef struct {
    WINDOW* border;
    WINDOW* prompt;
} PromptWindow;

static BYTE salt1[16] = {27, 130, 103, 40, 138, 19, 43, 13, 2, 228, 45, 26, 242, 232, 131, 247};
static BYTE salt2[16] = {50, 156, 173, 242, 26, 90, 239, 246, 139, 216, 70, 53, 254, 1, 198, 43};
static BYTE salt3[16] = {38, 201, 151, 231, 208, 219, 244, 17, 111, 186, 53, 122, 21, 239, 173, 155};

int SaveData(LoginData* data, Key* key);
unsigned int Menu(int height, int width, int y, int x, char** options, unsigned int options_count, unsigned int start_option);

unsigned int max(unsigned int a, unsigned int b){
    return a > b ? a : b;
}

unsigned int min(unsigned int a, unsigned int b){
    return a < b ? a : b;
}


void printErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void Initialize(){
    
    ERR_load_crypto_strings();
    
    
    OpenSSL_add_all_algorithms();
    
    
    //OPENSSL_config(NULL);
}

void Finalize(){
    
    EVP_cleanup();
    
    
    CRYPTO_cleanup_all_ex_data();
    
    
    ERR_free_strings();
}

unsigned int encrypt(BYTE *plaintext, unsigned int plaintext_len, BYTE *key, BYTE *iv, BYTE *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    
    unsigned int len;
    
    unsigned int ciphertext_len;
    
    
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();
    
    
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    
    ciphertext_len = len;
    
    
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;
    
    
    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
}

unsigned int decrypt(BYTE *ciphertext, unsigned int ciphertext_len, BYTE *key,BYTE *iv, BYTE *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    
    unsigned int len;
    
    unsigned int plaintext_len;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    
    
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();
    
    
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;
    
    
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;
    
    
    EVP_CIPHER_CTX_free(ctx);
    
    return plaintext_len;
}

int create_hmac(BYTE *msg, unsigned int message_lenght, BYTE *val, EVP_PKEY *pkey)
{
    /* Returned to caller */
    int result = 0;
    EVP_MD_CTX* ctx = NULL;
    size_t req = 0;
    int rc;
    
    
    
    
    
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        handleErrors();
    }
    
    rc = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    if (rc != 1) {
        handleErrors();
    }
    
    rc = EVP_DigestSignUpdate(ctx, msg, message_lenght);
    if (rc != 1) {
        handleErrors();
    }
    
    rc = EVP_DigestSignFinal(ctx, NULL, &req);
    if (rc != 1) {
        handleErrors();
    }
    
    
    
    size_t vlen = 0;
    rc = EVP_DigestSignFinal(ctx, val, &vlen);
    if (rc != 1) {
        handleErrors();
    }
    
    result = 1;
    
    
    EVP_MD_CTX_free(ctx);
    
    
    return result;
}

int verify_hmac(BYTE *msg, unsigned int message_lenght, BYTE *val, EVP_PKEY *pkey)
{
    /* Returned to caller */
    int result = 0;
    EVP_MD_CTX* ctx = NULL;
    BYTE buff[32];
    size_t size;
    int rc;
    
    
    
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        handleErrors();
    }
    
    rc = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    if (rc != 1) {
        handleErrors();
    }
    
    rc = EVP_DigestSignUpdate(ctx, msg, message_lenght);
    if (rc != 1) {
        handleErrors();
    }
    
    size = sizeof(buff);
    rc = EVP_DigestSignFinal(ctx, buff, &size);
    if (rc != 1) {
        handleErrors();
    }
    
    result = (32 == size) && (CRYPTO_memcmp(val, buff, size) == 0);
    
    EVP_MD_CTX_free(ctx);
    return result;
}



int RandomIV(BYTE* iv){
    return RAND_bytes(iv, 16);
}

void derive_key(BYTE* password, unsigned int password_lenght, BYTE* salt, BYTE* key, unsigned int iter){
    PKCS5_PBKDF2_HMAC(password, password_lenght, salt, 16, iter, EVP_sha256(), 32, key);
}

void hash_sha256(BYTE* message, unsigned int message_lenght, BYTE* digest){
    EVP_MD_CTX *mdctx;
    
	if((mdctx = EVP_MD_CTX_new()) == NULL)
		handleErrors();
    
	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handleErrors();
    
	if(1 != EVP_DigestUpdate(mdctx, message, message_lenght))
		handleErrors();
    
    
	if(1 != EVP_DigestFinal_ex(mdctx, digest, NULL))
		handleErrors();
    
	EVP_MD_CTX_free(mdctx);
}

void generate_token(Key* key, BYTE* token){
    BYTE concat[64];
    
    memcpy(concat, key->key, 32);
    memcpy(concat + 32, key->m_key, 32);
    
    hash_sha256(concat, 64, token);
    
}

// NOTE(fungus): return 0 if verified
int verify_key(Key* key, BYTE* token){
    BYTE digest[32];
    
    generate_token(key, digest);
    
    return CRYPTO_memcmp(digest, token, 32);
    
}

//void GetFixedInput(BYTE* buffer, unsigned int size, WINDOW* prompt){
//keypad(prompt, true);
//for (unsigned int i = 0; ; i++)
//{
//int input = wgetch(prompt);
//if(input == 10)
//break;
//else if(input == KEY_BACKSPACE){
//if(i > 0){
//wmove(prompt, getcury(prompt), getcurx(prompt)-1);
//wdelch(prompt);
//wrefresh(prompt);
//buffer[i-1] = 0;
//i -= 1;
//}
//i -= 1;
//continue;
//}
//else if(i == size - 2 || input >= KEY_MIN){
//i--;
//continue;
//}
//
//waddch(prompt, input);
//printw("%u", input);
// i == size - 2
//buffer[i] = input;
//buffer[i + 1] = 0;
//
//}
//keypad(prompt, false);
//}

void GetMainPassword(Key* key, char* prompt, WINDOW* w_prompt){
    BYTE password[INPUT_LIMIT];
    BYTE master_key[32];
    mvwprintw(w_prompt, 0, 0, prompt);
    
    wgetnstr(w_prompt, password, INPUT_LIMIT-1);
    
    derive_key(password, -1, salt1, master_key, N_ITERATIONS_MASTER);
    derive_key(master_key, 32, salt2, key->key, N_ITERATIONS_CHILD);
    derive_key(master_key, 32, salt3, key->m_key, N_ITERATIONS_CHILD);
    
}

int GetPath(LoginData* data, char* prompt, WINDOW* w_prompt){
    mvwprintw(w_prompt, 0, 0, prompt);
    
    wgetnstr(w_prompt, data->path, PATH_LIMIT);
    return access(data->path, F_OK);
}

int AddEntry(Key* key, LoginData* data, WINDOW* w_prompt){
    
    
    
    BYTE *login = (BYTE*)malloc(sizeof(BYTE) * INPUT_LIMIT);
    unsigned int login_size;
    
    
    
    while(1){
        
        char unique = 1;
        
        mvwprintw(w_prompt, 0, 0, "Enter login: ");
        
        wgetnstr(w_prompt, login, INPUT_LIMIT-1);
        login_size = strlen(login) + 1;
        
        for (unsigned i = 0; i < data->pair_count; i++)
        {
            if(!strcmp(login, data->loginPairs[i].login)){
                mvwprintw(w_prompt, 1, 0, "Login already used.\n");
                wgetch(w_prompt);
                unique = 0;
                break;
            }   
        }
        
        if(unique)
            break;
        
    }
    
    wclear(w_prompt);
    
    BYTE* encryptedPassword;
    BYTE iv[16];
    short password_block_count;
    
    
    mvwprintw(w_prompt, 0, 0, "Do you want to generate a strong password? (y/n)");
    int ans = wgetch(w_prompt);
    wclear(w_prompt);
    wrefresh(w_prompt);
    
    
    if(ans == 'N'  || ans == 'n')
    {
        BYTE password[INPUT_LIMIT];
        
        
        mvwprintw(w_prompt, 0, 0, "Enter password: ");
        wgetnstr(w_prompt, password, INPUT_LIMIT-1);
        unsigned int password_size = strlen(password) + 1;
        password_block_count = (password_size + 15) / 16;
        
        RandomIV(iv);
        
        encryptedPassword = (BYTE*)malloc(password_block_count * 16);
        password_block_count = encrypt(password, password_size, key->m_key, iv, encryptedPassword) / 16;
    }
    else
    {
        char password_size_s[4];
        mvwprintw(w_prompt, 0, 0, "Enter password lenght (recommended: 16-64): ");
        wgetnstr(w_prompt, password_size_s , 3);
        
        unsigned int password_size = max(1, min(atoi(password_size_s), 128)) + 1;
        unsigned int raw_password_size = (unsigned int)ceilf((float)(password_size - 1.f) * 0.75f);
        
        BYTE raw_password[raw_password_size];
        
        RAND_bytes(raw_password, raw_password_size);
        
        
        // 4 characters -> 3 bytes
        
        BYTE password_buffer[INPUT_LIMIT];
        BYTE password[password_size];
        
        EVP_EncodeBlock(password_buffer, raw_password, raw_password_size);
        memcpy(password, password_buffer, password_size - 1);
        password[password_size-1] = 0;
        
        password_block_count = (password_size + 15) / 16;
        
        RandomIV(iv);
        
        encryptedPassword = (BYTE*)malloc(password_block_count * 16);
        password_block_count = encrypt(password, password_size, key->m_key, iv, encryptedPassword) / 16;
        
    }
    
    data->loginPairs = (LoginPair*)realloc(data->loginPairs, (data->pair_count + 1) * sizeof(LoginPair));
    
    data->loginPairs[data->pair_count].login_size = login_size;
    data->loginPairs[data->pair_count].password_block_count = password_block_count;
    
    // data->loginPairs[data->pair_count].password_iv = iv;
    memcpy(data->loginPairs[data->pair_count].password_iv, iv, 16);
    
    data->loginPairs[data->pair_count].login = login;
    data->loginPairs[data->pair_count].password = encryptedPassword;
    (data->pair_count)++;
    
    
    SaveData(data, key);
    
}

void RemoveEntry(LoginData* data, unsigned int index, Key* key){
    free(data->loginPairs[index].login);
    free(data->loginPairs[index].password);
    
    for (unsigned int i = index + 1; i < data->pair_count; i++)
    {
        data->loginPairs[i - 1] = data->loginPairs[i];
    }
    data->loginPairs = (LoginPair*)realloc(data->loginPairs, (data->pair_count - 1) * sizeof(LoginPair));
    data->pair_count--;
    
    SaveData(data, key);
}

void ShowPassword(LoginData* data, unsigned int index, Key* key, int copy, WINDOW* prompt){
    BYTE password[data->loginPairs[index].password_block_count * 16];
    
    decrypt(data->loginPairs[index].password, data->loginPairs[index].password_block_count * 16, key->m_key, data->loginPairs[index].password_iv, password);
    
    if(copy){
        char command[INPUT_LIMIT];
        sprintf(command, "printf %s | xclip -sel clip", password);
        system(command);
        return;
    }
    mvwprintw(prompt, 0, 0, "Password: %s\n", password);
    
    // data->loginPairs[index].password_iv = iv;
}


// returns false if decryption fails
int LoadData(LoginData* data, Key* key){
    FILE* fp;
    fp = fopen(data->path, "rb");
    
    unsigned short ciphertext_block_count;
    fread(&(ciphertext_block_count), 2, 1, fp);
    
    if(!ciphertext_block_count){
        //generate_token(key, data->key_token);
        return 0;
    }
    
    BYTE ciphertext[ciphertext_block_count * 16];
    BYTE main_iv[16];
    BYTE mac[32];
    BYTE message[ciphertext_block_count * 16 + 16];
    BYTE* cleartext = (BYTE*)malloc(ciphertext_block_count * 16);
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
    
    BYTE* current_pointer = cleartext;
    memcpy(&(data->pair_count), current_pointer, 4);
    current_pointer += 4;
    
    // TODO(fungus): add metadata
    // time (4 bytes) number of iv generations (4 bytes) something else (8 bytes)
    current_pointer += 4 + 4 + 8;
    
    
    data->loginPairs = (LoginPair*)malloc(sizeof(LoginPair) * data->pair_count);
    for (unsigned int i = 0; i < data->pair_count; i++)
    {
        unsigned int login_size;
        unsigned short password_block_count; // 128-bit blocks (16 byte)
        
        memcpy(&login_size, current_pointer, 4);
        
        current_pointer += 4;
        memcpy(&password_block_count, current_pointer, 2);
        current_pointer += 2;
        
        data->loginPairs[i].login_size = login_size;
        data->loginPairs[i].password_block_count = password_block_count;
        data->loginPairs[i].login = (BYTE*)malloc(login_size);
        data->loginPairs[i].password = (BYTE*)malloc(password_block_count * 16);
        
        
        memcpy(data->loginPairs[i].login, current_pointer, login_size);
        current_pointer += login_size;
        
    }
    // for (unsigned int i = 0; i < data->pair_count; i++)
    // {
    //     fread(data->loginPairs[i].password, data->loginPairs[i].password_block_count * 16, 1, fp);
    //     fread(data->loginPairs[i].password_iv, 16, 1, fp);
    // }
    for (int i = 0; i < data->pair_count; i++)
    {
        memcpy(data->loginPairs[i].password, current_pointer, data->loginPairs[i].password_block_count * 16);
        current_pointer += data->loginPairs[i].password_block_count * 16;
        memcpy(data->loginPairs[i].password_iv, current_pointer, 16);
        current_pointer += 16;
    }
    
    
    
    
    fclose(fp);
    free(cleartext);
    return 1;
}

// return false if failed
int SaveData(LoginData* data, Key* key){
    if(verify_key(key, data->key_token)){
        return 0;
    }
    
    FILE* file_ptr;
    file_ptr = fopen(data->path, "wb");
    // TODO(fungus): add metadata
    // time (4 bytes) number of iv generations (4 bytes) something else (8 bytes)
    unsigned int cleartext_size = sizeof(data->pair_count) + 4 + 4 + 8;
    for (int i = 0; i < data->pair_count; i++)
    {
        cleartext_size += sizeof(unsigned int) + sizeof(unsigned short) + data->loginPairs[i].login_size + data->loginPairs[i].password_block_count * 16 + 16;
    }
    BYTE ciphertext[((cleartext_size + 15) / 16) * 16 + 16];
    BYTE* cleartext_to_encrypt = (BYTE*)malloc(cleartext_size);
    BYTE* current_pointer = cleartext_to_encrypt;
    //BYTE* start_pointer = current_pointer;
    
    memcpy(current_pointer, &(data->pair_count), 4);
    current_pointer += 4;
    
    current_pointer += 4 + 4 + 8;
    
    for (unsigned int i = 0; i < data->pair_count; i++)
    {
        memcpy(current_pointer, &(data->loginPairs[i].login_size), 4);
        current_pointer += 4;
        memcpy(current_pointer, &(data->loginPairs[i].password_block_count), 2);
        current_pointer += 2;
        memcpy(current_pointer, data->loginPairs[i].login, data->loginPairs[i].login_size);
        current_pointer += data->loginPairs[i].login_size;
    }
    // fwrite(data->login_iv, 16, 1, file_ptr);
    // for (unsigned int i = 0; i < data->pair_count; i++)
    // {
    //     fwrite(data->loginPairs[i].password, data->loginPairs[i].password_block_count * 16, 1, file_ptr);
    //     fwrite(data->loginPairs[i].password_iv, 16, 1, file_ptr);
    // }
    
    
    
    for (int i = 0; i < data->pair_count; i++)
    {
        memcpy(current_pointer, data->loginPairs[i].password, data->loginPairs[i].password_block_count * 16);
        current_pointer += data->loginPairs[i].password_block_count * 16;
        memcpy(current_pointer, data->loginPairs[i].password_iv, 16);
        current_pointer += 16;
    }
    
    
    BYTE iv[16];
    BYTE mac[32] = {0};
    RandomIV(iv);
    
    // memcpy(current_pointer, data->main_iv, 16);
    // current_pointer += 16;
    
    unsigned short ciphertext_block_count = encrypt(cleartext_to_encrypt, cleartext_size, key->key, iv, ciphertext) / 16;
    
    BYTE message[ciphertext_block_count * 16 + 16];
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
    return 1;
}

unsigned int Menu(int height, int width, int y, int x, char** options, unsigned int options_count, unsigned int start_option){
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

// NOTE(fungus): this clears the prompt window
unsigned int YesOrNo(WINDOW* w_prompt, char* prompt){
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

unsigned int ChooseMenu(){
    char * options[] = {"Create password bank", "Open password bank", "Exit"};
    return Menu(3, 30, getmaxy(stdscr)/2-3 , getmaxx(stdscr)/2-17, options, 3, 0);
}

void InitializeData(LoginData* data){
    data->pair_count = 0;
    data->loginPairs = NULL;
    memset(data->key_token, 0, 32);
    memset(data->path, 0, PATH_LIMIT);
}

void DestroyData(LoginData* data){
    for (unsigned int i = 0; i < data->pair_count; i++)
    {
        free(data->loginPairs[i].login);
        free(data->loginPairs[i].password);
    }
    if(data->loginPairs)
        free(data->loginPairs);
}

int main(){
    Initialize();
    initscr();
    getch(); //4coder
    cbreak();
    //noecho();
    //keypad(stdscr, 1);
    //curs_set(0);
    if(has_colors()){
        start_color();
        use_default_colors();
    }
    
    // TODO(fungus): make better inputs, make a 30s clipboard reset, add entry manipulation options (renaming, etc.), add option to change password, add file encryption, test, add comments, clean code etc.
    
    int max_y, max_x;
    
    getmaxyx(stdscr, max_y, max_x);
    
    // UP_ARROW = KEY_UP
    // DOWN_ARROW = KEY_DOWN
    
    LoginData data;
    InitializeData(&data);
    
    //unsigned int mode = ModeChooseMenu();
    
    PromptWindow prompt_window;
    prompt_window.border = newwin(max_y/3, max_x, 0, 0);
    prompt_window.prompt = derwin(prompt_window.border, max_y/3 - 2, max_x - 4, 1, 2);
    
    
    box(prompt_window.border, 0, 0);
    wrefresh(prompt_window.border);
    
    first_menu:
    unsigned int first_option = ChooseMenu();
    
    if(first_option == 2){
        endwin();
        return 0;
    }
    
    if(!first_option){
        // TODO(fungus): error checking
        
        vault_create:
        if(!GetPath(&data, "Enter new vault path and name: ", prompt_window.prompt)){
            
            unsigned int ans = YesOrNo(prompt_window.prompt, "File already exists. Do you want to override? (y/n)");
            if(!ans)
                goto first_menu;
            
        }
        
        {
            
            char vault_prompt[INPUT_LIMIT];
            
            sprintf(vault_prompt, "Do you want to create a new vault at: \"%s\"? (y/n)", data.path);
            
            unsigned int ans = YesOrNo(prompt_window.prompt, vault_prompt);
            if(!ans)
                goto first_menu;
            
            Key key;
            
            GetMainPassword(&key, "Enter new vault password: ", prompt_window.prompt);
            
            
            wclear(prompt_window.prompt);
            wrefresh(prompt_window.prompt);
            
            generate_token(&key, data.key_token);
            
            
            SaveData(&data, &key);
        }
        
    }
    else {
        if(GetPath(&data, "Enter vault path: ", prompt_window.prompt)){
            unsigned int ans = YesOrNo(prompt_window.prompt, "File does not exist. Do you want to create a new one? (y/n)");
            if(ans)
                goto vault_create;
            else
                goto first_menu;
        }
        wclear(prompt_window.prompt);
        pass:
        {
            Key key;
            
            
            GetMainPassword(&key, "Enter vault password: ", prompt_window.prompt);
            wclear(prompt_window.prompt);
            wrefresh(prompt_window.prompt);
            
            if(!LoadData(&data, &key)){
                mvwprintw(prompt_window.prompt, 0, 0, "Invalid password. Do you want to try again? (y/n)");
                unsigned int ans = YesOrNo(prompt_window.prompt, "Invalid password. Do you want to try again? (y/n)");
                if(ans == 'Y'  || ans == 'y')
                    goto pass;
                goto first_menu;
            }
            
        }
        
    }
    
    clear();
    refresh();
    box(prompt_window.border, 0, 0);
    wrefresh(prompt_window.border);
    
    
    
    char **options = (char**)malloc(sizeof(char*) * (data.pair_count+3));
    for(int i = 0; i < data.pair_count; ++i){
        options[i] = data.loginPairs[i].login;
    }
    options[data.pair_count] = (char*)"Add entry";
    options[data.pair_count + 1] = (char*)"Remove entry";
    options[data.pair_count + 2] = (char*)"Exit";
    
    unsigned int last_option = 0;
    
    
    
    while(1){
        
        last_option = Menu(data.pair_count+3, getmaxx(stdscr)/2, getmaxy(stdscr)/2-(data.pair_count+3)/2 , getmaxx(stdscr)/2-(getmaxx(stdscr)/4), options, data.pair_count+3, last_option);
        if(last_option < data.pair_count){
            
            pass_show:
            {
                wclear(prompt_window.prompt);
                
                
                Key key;
                
                GetMainPassword(&key, "Enter vault password: ", prompt_window.prompt);
                
                
                if(!verify_key(&key, data.key_token)){
                    
                    wclear(prompt_window.prompt);
                    ShowPassword(&data, last_option, &key, 1, prompt_window.prompt);
                    mvwprintw(prompt_window.prompt, 0 ,0, "Password copied to clipboard.");
                    wrefresh(prompt_window.prompt);
                }
                else{
                    unsigned int ans = YesOrNo(prompt_window.prompt, "Invalid password. Do you want to try again? (y/n)");
                    if(ans)
                        goto pass_show;
                    
                }
                
            }
        }
        else if(last_option == data.pair_count){
            pass_add:
            {
                
                wclear(prompt_window.prompt);
                
                
                Key key;
                
                GetMainPassword(&key, "Enter vault password: ", prompt_window.prompt);
                
                
                if(!verify_key(&key, data.key_token)){
                    wclear(prompt_window.prompt);
                    AddEntry(&key, &data, prompt_window.prompt);
                    
                    
                    
                    wclear(prompt_window.prompt);
                    wrefresh(prompt_window.prompt);
                }
                else{
                    unsigned int ans = YesOrNo(prompt_window.prompt, "Invalid password. Do you want to try again? (y/n)");
                    if(ans)
                        goto pass_add;
                    
                }
            }
            
            
            
            options = (char**)realloc(options, sizeof(char*) * (data.pair_count+3));
            
            options[data.pair_count-1] = data.loginPairs[data.pair_count-1].login; 
            options[data.pair_count] = "Add entry";
            options[data.pair_count + 1] = "Remove entry";
            options[data.pair_count + 2] = "Exit";
            
        }
        else if(last_option == data.pair_count+1){
            {
                wclear(prompt_window.prompt);
                
                
                Key key;
                
                GetMainPassword(&key, "Enter vault password: ", prompt_window.prompt);
                
                
                if(!verify_key(&key, data.key_token)){
                    last_option = 0;
                    
                    pass_rem:
                    char *rem_options[data.pair_count+1];
                    
                    for (int i = 0; i < data.pair_count; i += 1){
                        rem_options[i] = data.loginPairs[i].login;
                    }
                    
                    rem_options[data.pair_count] = "Exit";
                    
                    wclear(prompt_window.prompt);
                    mvwprintw(prompt_window.prompt, 0, 0, "Choose entry to remove...");
                    wrefresh(prompt_window.prompt);
                    
                    clear();
                    refresh();
                    box(prompt_window.border, 0, 0);
                    wrefresh(prompt_window.border);
                    
                    unsigned int to_remove = Menu(data.pair_count+1, getmaxx(stdscr)/2, getmaxy(stdscr)/2-(data.pair_count+3)/2 , getmaxx(stdscr)/2-(getmaxx(stdscr)/4), rem_options, data.pair_count+1, 0);
                    
                    
                    
                    if(to_remove == data.pair_count){
                        clear();
                        refresh();
                        box(prompt_window.border, 0, 0);
                        wrefresh(prompt_window.border);
                        wclear(prompt_window.prompt);
                        wrefresh(prompt_window.prompt);
                        continue;
                    }
                    else{
                        //char remove_prompt[strlen(data.loginPairs[to_remove].login) + 17];
                        char remove_prompt[INPUT_LIMIT];
                        sprintf(remove_prompt, "Remove \"%s\"? (y/n)", data.loginPairs[to_remove].login);
                        
                        unsigned int ans = YesOrNo(prompt_window.prompt, remove_prompt);
                        if(!ans)
                            goto pass_rem;
                        
                        RemoveEntry(&data, to_remove, &key);
                        clear();
                        refresh();
                        box(prompt_window.border, 0, 0);
                        wrefresh(prompt_window.border);
                    }
                    
                    
                    
                }
                else{
                    unsigned int ans = YesOrNo(prompt_window.prompt, "Invalid password. Do you want to try again? (y/n)");
                    if(ans)
                        goto pass_add;
                    
                }
                
                options = (char**)realloc(options, sizeof(char*) * (data.pair_count+3));
                
                for(int i = 0; i < data.pair_count; ++i){
                    options[i] = data.loginPairs[i].login;
                }
                
                options[data.pair_count] = "Add entry";
                options[data.pair_count + 1] = "Remove entry";
                options[data.pair_count + 2] = "Exit";
                
            }
        }
        else{
            wclear(prompt_window.prompt);
            mvwprintw(prompt_window.prompt, 0, 0, "Do you want to exit? (y/n)");
            int ans = wgetch(prompt_window.prompt);
            wclear(prompt_window.prompt);
            wrefresh(prompt_window.prompt);
            if(ans == 'Y'  || ans == 'y')
                break;
        }
    }
    
    
    
    free(options);
    DestroyData(&data);
    endwin();
    Finalize();
}