#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ncurses.h>

#include "input.h"

#include "global_types.h"
#include "data.h"

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

unsigned int get_uint(char* prompt, WINDOW* w_prompt){
    char input[INPUT_LIMIT];
    
    mvwprintw(w_prompt, 0, 0, prompt);
    wgetnstr(w_prompt, input, INPUT_LIMIT-1);
    
    return (unsigned int)MIN(strtoul(input, NULL, 10), UINT_MAX);
}

void random_password(unsigned int password_size, byte* password){
    unsigned int raw_password_size = (unsigned int)ceilf((float)(password_size - 1) * 0.75f);
    
    byte raw_password[raw_password_size];
    
    RAND_bytes(raw_password, raw_password_size);
    
    byte password_buffer[((unsigned int)ceilf(raw_password_size * 1.25f) + 3)/4 * 4 + 1];
    
    EVP_EncodeBlock(password_buffer, raw_password, raw_password_size);
    memcpy(password, password_buffer, password_size - 1);
    password[password_size - 1] = 0;
}