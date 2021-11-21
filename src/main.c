#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <math.h>
#include <limits.h>
#include <ncurses.h>

#include "global_types.h"

#define _DEBUG
#include "crypto.h"
#include "data.h"
#include "input.h"

typedef struct {
    WINDOW* border;
    WINDOW* prompt;
} prompt_window;



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
    
    // TODO(fungus): make better inputs, make a 30s clipboard reset, add file encryption, test, add comments, clean up code etc.
    // TODO(fungus): clean up file hierarchy etc.
    
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
            
            random_salt(data.master_salt);
            
            byte master_key[32];
            
            {
                byte password[INPUT_LIMIT];
                unsigned int password_size = get_password(password, "Enter new vault password: ", w_prompt.prompt);
                
                derive_master_key(password, password_size, data.master_salt, master_key);
            }
            
            key_group keys;
            get_keys(master_key, &keys);
            
            generate_token(master_key, data.key_token);
            
            wclear(w_prompt.prompt);
            wrefresh(w_prompt.prompt);
            
            save_data(&data, &keys);
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
            load_master_salt(&data);
            
            byte master_key[32];
            
            {
                byte password[INPUT_LIMIT];
                unsigned int password_size = get_password(password, "Enter vault password: ", w_prompt.prompt);
                
                derive_master_key(password, password_size, data.master_salt, master_key);
            }
            
            key_group keys;
            get_keys(master_key, &keys);
            
            wclear(w_prompt.prompt);
            wrefresh(w_prompt.prompt);
            
            if(!load_data(&data, &keys)){
                unsigned int ans = yes_no_prompt("Invalid password. Do you want to try again? (y/n)", w_prompt.prompt);
                if(ans)
                    goto pass;
                goto first_menu;
            }
            
            generate_token(master_key, data.key_token);
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
                
                byte master_key[32];
                
                {
                    byte password[INPUT_LIMIT];
                    unsigned int password_size = get_password(password, "Enter vault password: ", w_prompt.prompt);
                    
                    derive_master_key(password, password_size, data.master_salt, master_key);
                }
                
                if(!verify_key(master_key, data.key_token)){
                    wclear(w_prompt.prompt);
                    
                    key_group keys;
                    get_keys(master_key, &keys);
                    
                    byte password[data.login_pairs[last_option].password_block_count * 16];
                    decrypt_entry(&data, last_option, &keys, password);
                    
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
                
                byte master_key[32];
                
                {
                    byte password[INPUT_LIMIT];
                    unsigned int password_size = get_password(password, "Enter vault password: ", w_prompt.prompt);
                    
                    derive_master_key(password, password_size, data.master_salt, master_key);
                }
                
                if(!verify_key(master_key, data.key_token)){
                    wclear(w_prompt.prompt);
                    
                    key_group keys;
                    get_keys(master_key, &keys);
                    
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
                    
                    add_entry(&data, &keys, login, login_size, password, password_size);
                    
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
            
            byte master_key[32];
            
            {
                byte password[INPUT_LIMIT];
                unsigned int password_size = get_password(password, "Enter vault password: ", w_prompt.prompt);
                
                derive_master_key(password, password_size, data.master_salt, master_key);
            }
            
            if(!verify_key(master_key, data.key_token)){
                last_option = 0;
                
                key_group keys;
                get_keys(master_key, &keys);
                
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
                    
                    remove_entry(&data, to_remove, &keys);
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
            
            byte master_key[32];
            
            {
                byte password[INPUT_LIMIT];
                unsigned int password_size = get_password(password, "Enter vault password: ", w_prompt.prompt);
                
                derive_master_key(password, password_size, data.master_salt, master_key);
            }
            
            if(!verify_key(master_key, data.key_token)){
                key_group keys;
                get_keys(master_key, &keys);
                
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
                        change_entry_login(&data, to_change, &keys, new_login, new_login_size);
                    if(new_password_size - 1)
                        change_entry_password(&data, to_change, &keys, new_password, new_password_size);
                    
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
            
            byte old_master_key[32];
            
            {
                byte password[INPUT_LIMIT];
                unsigned int password_size = get_password(password, "Enter old vault password: ", w_prompt.prompt);
                
                derive_master_key(password, password_size, data.master_salt, old_master_key);
            }
            
            if(!verify_key(old_master_key, data.key_token)){
                key_group old_keys;
                get_keys(old_master_key, &old_keys);
                
                wclear(w_prompt.prompt);
                
                byte new_master_key[32];
                
                {
                    byte password[INPUT_LIMIT];
                    unsigned int password_size = get_password(password, "Enter new vault password: ", w_prompt.prompt);
                    
                    derive_master_key(password, password_size, data.master_salt, new_master_key);
                }
                
                key_group new_keys;
                get_keys(new_master_key, &new_keys);
                
                unsigned int ans = yes_no_prompt("Are you sure you want to change the vault's password? (y/n)", w_prompt.prompt);
                
                if(ans){
                    generate_token(new_master_key, data.key_token);
                    change_vault_password(&data, &old_keys, &new_keys);
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