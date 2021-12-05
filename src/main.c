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
    WINDOW *border;
    WINDOW *prompt;
} prompt_window;



u32 create_menu(i32 height, i32 width, i32 y, i32 x, char **options, u32 options_count, u32 start_option){
    i32 curs_vis = curs_set(0);
    
    WINDOW *menu_border = newwin(height + 2, width + 4, y - 1, x - 2);
    WINDOW *menu = derwin(menu_border, height, width, 1, 2);
    
    keypad(menu, true);
    
    box(menu_border, 0, 0);
    wrefresh(menu_border);
    
    u32 selected = start_option;
    
    while(1){
        for (u32 i = 0; i < options_count; i++)
        {   
            if(i == selected)
                wattron(menu, A_STANDOUT);
            
            mvwprintw(menu, i, 0, "%-*s", width, options[i]);
            
            wattroff(menu, A_STANDOUT);
        }
        
        touchwin(menu_border);
        i32 input = wgetch(menu);
        
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


u32 yes_no_prompt(char *prompt, WINDOW* w_prompt){
    noecho();
    
    wclear(w_prompt);
    mvwprintw(w_prompt, 0, 0, prompt);
    
    i32 ans = 0;
    do
    {
        ans = wgetch(w_prompt);
        
    } while(ans != 'y' && ans != 'Y' && ans != 'n' && ans != 'N');
    
    wclear(w_prompt);
    wrefresh(w_prompt);
    
    echo();
    
    return ans == 'y' || ans == 'Y' ? 1 : 0;
}

i32 main(){
    initialize();
    initscr();
    getch(); // 4coder
    cbreak();
    
    if(has_colors()){
        start_color();
        use_default_colors();
    }
    
    // TODO(fungus): make better inputs, make a 30s clipboard reset, add file encryption, test, add comments, clean up code, do a complete menu look overhaul, etc.
    // TODO(fungus): clean up file hierarchy etc.
    // TODO(fungus): use size_t 
    // TODO(fungus): do error checking
    // TODO(fungus): remove goto's <-
    // TODO(fungus): stop yes or no function from refreshing
    // TODO(fungus): minimize prompt refreshing
    // TODO(fungus): fix warnings
    // TODO(fungus): (maybe) use do while loops
    // TODO(fungus): shorten yes or no
    
    i32 height, width;
    getmaxyx(stdscr, height, width);
    
    login_data data;
    initialize_data(&data);
    
    prompt_window w_prompt;
    w_prompt.border = newwin(height/3, width, 0, 0);
    w_prompt.prompt = derwin(w_prompt.border, height/3 - 2, width - 4, 1, 2);
    
    box(w_prompt.border, 0, 0);
    wrefresh(w_prompt.border);
    
    while(1){
        wclear(w_prompt.prompt);
        wrefresh(w_prompt.prompt);
        
        char *first_options[] = {"Create password bank", "Open password bank", "Exit"};
        u32 first_option = create_menu(3, 30, height/2-3 , width/2-17, first_options, 3, 0);
        
        if(!first_option){
            vault_create:
            
            if(!get_path(data.path, "Enter new vault path and name: ", w_prompt.prompt)){
                u32 ans = yes_no_prompt("File already exists. Do you want to override? (y/n)", w_prompt.prompt);
                if(!ans)
                    continue;
            }
            
            char vault_prompt[INPUT_LIMIT];
            
            sprintf(vault_prompt, "Do you want to create a new vault at: \"%s\"? (y/n)", data.path);
            
            u32 ans = yes_no_prompt(vault_prompt, w_prompt.prompt);
            if(!ans)
                continue;
            
            random_salt(data.master_salt);
            
            byte master_key[32];
            
            {
                byte password[INPUT_LIMIT];
                u32 password_size = get_password(password, "Enter new vault password: ", w_prompt.prompt);
                
                wclear(w_prompt.prompt);
                wrefresh(w_prompt.prompt);
                
                derive_master_key(password, password_size, data.master_salt, master_key);
            }
            
            key_group keys;
            get_keys(master_key, &keys);
            
            generate_token(master_key, data.key_token);
            
            save_data(&data, &keys);
        }
        else if(first_option == 1){
            if(get_path(data.path, "Enter vault path: ", w_prompt.prompt)){
                u32 ans = yes_no_prompt("File does not exist. Do you want to create a new one? (y/n)", w_prompt.prompt);
                if(ans)
                    goto vault_create;
                continue;
            }
            
            load_master_salt(&data);
            
            while(1){
                byte master_key[32];
                
                {
                    byte password[INPUT_LIMIT];
                    u32 password_size = get_password(password, "Enter vault password: ", w_prompt.prompt);
                    
                    wclear(w_prompt.prompt);
                    wrefresh(w_prompt.prompt);
                    
                    derive_master_key(password, password_size, data.master_salt, master_key);
                }
                
                key_group keys;
                get_keys(master_key, &keys);
                
                if(!load_data(&data, &keys)){
                    u32 ans = yes_no_prompt("Invalid password. Do you want to try again? (y/n)", w_prompt.prompt);
                    if(ans)
                        continue;
                }
                
                generate_token(master_key, data.key_token);
                break;
            }
        }
        else if(first_option == 2){
            endwin();
            return 0;
        }
        break;
    }
    
    clear();
    refresh();
    box(w_prompt.border, 0, 0);
    wrefresh(w_prompt.border);
    
    // TODO(fungus): move Change vault password to other menu
    const u32 extra_options_count = 5;
    char *extra_options[5] = {
        "Add entry",
        "Remove entry",
        "Change entry",
        "Change vault password",
        "Exit"
    };
    
    char **options = malloc(sizeof(char*) * (data.pair_count+extra_options_count));
    for(i32 i = 0; i < data.pair_count; ++i){
        options[i] = data.login_pairs[i].login;
    }
    
    memcpy(&options[data.pair_count], extra_options, extra_options_count * sizeof(char*));
    
    u32 last_option = 0;
    
    while(1){ // Main loop
        last_option = create_menu(data.pair_count+extra_options_count, width/2,
                                  height/2-(data.pair_count+3)/2 , width/2-(width/4),
                                  options, data.pair_count+extra_options_count, last_option);
        
        if(last_option < data.pair_count){ // Show entry
            while(1){
                wclear(w_prompt.prompt);
                
                byte master_key[32];
                
                {
                    byte password[INPUT_LIMIT];
                    u32 password_size = get_password(password, "Enter vault password: ", w_prompt.prompt);
                    
                    wclear(w_prompt.prompt);
                    wrefresh(w_prompt.prompt);
                    
                    derive_master_key(password, password_size, data.master_salt, master_key);
                }
                
                if(!verify_key(master_key, data.key_token)){
                    key_group keys;
                    get_keys(master_key, &keys);
                    
                    byte password[data.login_pairs[last_option].enc_password_size];
                    decrypt_entry(&data, last_option, &keys, password);
                    
                    copy_to_clipboard(password);
                    
                    mvwprintw(w_prompt.prompt, 0 ,0, "Password copied to clipboard.");
                    wrefresh(w_prompt.prompt);
                }
                else{
                    u32 ans = yes_no_prompt("Invalid password. Do you want to try again? (y/n)", w_prompt.prompt);
                    if(ans)
                        continue;
                }
                break;
            }
        }
        else if(last_option == data.pair_count){ // Add entry
            while(1){
                wclear(w_prompt.prompt);
                
                byte master_key[32];
                
                {
                    byte password[INPUT_LIMIT];
                    u32 password_size = get_password(password, "Enter vault password: ", w_prompt.prompt);
                    
                    wclear(w_prompt.prompt);
                    wrefresh(w_prompt.prompt);
                    
                    derive_master_key(password, password_size, data.master_salt, master_key);
                }
                
                if(!verify_key(master_key, data.key_token)){
                    key_group keys;
                    get_keys(master_key, &keys);
                    
                    byte *login = malloc(sizeof(byte) * INPUT_LIMIT); 
                    u32 login_size = get_unique_login(&data, login, "Enter new login: ", w_prompt.prompt);
                    login = realloc(login, login_size);
                    
                    wclear(w_prompt.prompt);
                    
                    byte password[INPUT_LIMIT];
                    u32 password_size;
                    
                    u32 generate = yes_no_prompt("Do you want to generate a strong password? (y/n)", w_prompt.prompt);
                    wclear(w_prompt.prompt);
                    
                    if(generate){
                        password_size = get_uint("Enter password lenght (recommended 16-64): ", w_prompt.prompt) + 1;
                        random_password(password_size, password);
                    }
                    else{
                        password_size = get_password(password, "Enter password: ", w_prompt.prompt);
                    }
                    
                    wclear(w_prompt.prompt);
                    wrefresh(w_prompt.prompt);
                    
                    add_entry(&data, &keys, login, login_size, password, password_size);
                    
                    options = realloc(options, sizeof(char*) * (data.pair_count+extra_options_count));
                    
                    options[data.pair_count-1] = data.login_pairs[data.pair_count-1].login; 
                    memcpy(&options[data.pair_count], extra_options, extra_options_count * sizeof(char*));
                }
                else{
                    u32 ans = yes_no_prompt("Invalid password. Do you want to try again? (y/n)", w_prompt.prompt);
                    if(ans)
                        continue;
                }
                break;
            }
        }
        else if(last_option == data.pair_count+1){ // Remove entry
            while(1){
                wclear(w_prompt.prompt);
                
                byte master_key[32];
                
                {
                    byte password[INPUT_LIMIT];
                    u32 password_size = get_password(password, "Enter vault password: ", w_prompt.prompt);
                    
                    wclear(w_prompt.prompt);
                    wrefresh(w_prompt.prompt);
                    
                    derive_master_key(password, password_size, data.master_salt, master_key);
                }
                
                if(!verify_key(master_key, data.key_token)){
                    last_option = 0;
                    
                    key_group keys;
                    get_keys(master_key, &keys);
                    
                    char *rem_options[data.pair_count+1];
                    for (i32 i = 0; i < data.pair_count; i += 1){
                        rem_options[i] = data.login_pairs[i].login;
                    }
                    
                    rem_options[data.pair_count] = "Exit";
                    
                    while(1){
                        mvwprintw(w_prompt.prompt, 0, 0, "Choose entry to remove...");
                        wrefresh(w_prompt.prompt);
                        
                        clear();
                        refresh();
                        box(w_prompt.border, 0, 0);
                        wrefresh(w_prompt.border);
                        
                        u32 to_remove = create_menu(data.pair_count+1, width/2, 
                                                    height/2-(data.pair_count+3)/2 , width/2-(width/4),
                                                    rem_options, data.pair_count+1, 0);
                        
                        if(to_remove == data.pair_count){
                            clear();
                            refresh();
                            box(w_prompt.border, 0, 0);
                            wrefresh(w_prompt.border);
                            wclear(w_prompt.prompt);
                            wrefresh(w_prompt.prompt);
                        }
                        else{
                            char remove_prompt[INPUT_LIMIT];
                            sprintf(remove_prompt, "Remove \"%s\"? (y/n)", data.login_pairs[to_remove].login);
                            
                            u32 ans = yes_no_prompt(remove_prompt, w_prompt.prompt);
                            if(!ans)
                                continue;
                            
                            remove_entry(&data, to_remove, &keys);
                            clear();
                            refresh();
                            box(w_prompt.border, 0, 0);
                            wrefresh(w_prompt.border);
                            
                            options = realloc(options, sizeof(char*) * (data.pair_count+extra_options_count));
                            for(i32 i = 0; i < data.pair_count; ++i){
                                options[i] = data.login_pairs[i].login;
                            }
                            
                            memcpy(&options[data.pair_count], extra_options, extra_options_count * sizeof(char*));
                        }
                        break;
                    }
                }
                else{
                    u32 ans = yes_no_prompt("Invalid password. Do you want to try again? (y/n)", w_prompt.prompt);
                    if(ans)
                        continue;
                }
                break;
            }
        }
        else if(last_option == data.pair_count+2){ // Change entry
            while(1){
                wclear(w_prompt.prompt);
                
                byte master_key[32];
                
                {
                    byte password[INPUT_LIMIT];
                    u32 password_size = get_password(password, "Enter vault password: ", w_prompt.prompt);
                    
                    wclear(w_prompt.prompt);
                    wrefresh(w_prompt.prompt);
                    
                    derive_master_key(password, password_size, data.master_salt, master_key);
                }
                
                if(!verify_key(master_key, data.key_token)){
                    key_group keys;
                    get_keys(master_key, &keys);
                    
                    char *change_options[data.pair_count + 1];
                    for (i32 i = 0; i < data.pair_count; i += 1){
                        change_options[i] = data.login_pairs[i].login;
                    }
                    
                    change_options[data.pair_count] = "Exit";
                    
                    mvwprintw(w_prompt.prompt, 0, 0, "Choose entry to change...");
                    wrefresh(w_prompt.prompt);
                    
                    clear();
                    refresh();
                    box(w_prompt.border, 0, 0);
                    wrefresh(w_prompt.border);
                    
                    u32 to_change = create_menu(data.pair_count+1, width/2,
                                                height/2-(data.pair_count+3)/2 , width/2-(width/4),
                                                change_options, data.pair_count+1, 0);
                    
                    if(to_change == data.pair_count){
                        clear();
                        refresh();
                        box(w_prompt.border, 0, 0);
                        wrefresh(w_prompt.border);
                        wclear(w_prompt.prompt);
                        wrefresh(w_prompt.prompt);
                        break;
                    }
                    else{
                        wclear(w_prompt.prompt);
                        
                        byte *new_login = malloc(sizeof(byte) * INPUT_LIMIT); 
                        u32 new_login_size = get_unique_login(&data, new_login, "New login (leave blank if not changing): ", w_prompt.prompt);
                        
                        wclear(w_prompt.prompt);
                        wrefresh(w_prompt.prompt);
                        
                        new_login = realloc(new_login, new_login_size);
                        
                        byte new_password[INPUT_LIMIT];
                        u32 new_password_size = get_password(new_password, "New password (leave blank if not changing): ", w_prompt.prompt);
                        
                        wclear(w_prompt.prompt);
                        wrefresh(w_prompt.prompt);
                        
                        if(new_login_size - 1)
                            change_entry_login(&data, to_change, &keys, new_login, new_login_size);
                        else
                            free(new_login);
                        
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
                    u32 ans = yes_no_prompt("Invalid password. Do you want to try again? (y/n)", w_prompt.prompt);
                    if(ans)
                        continue;
                }
                break;
            }
        }
        else if(last_option == data.pair_count + 3){ // Change vault password
            while(1){
                wclear(w_prompt.prompt);
                
                byte old_master_key[32];
                
                {
                    byte password[INPUT_LIMIT];
                    u32 password_size = get_password(password, "Enter old vault password: ", w_prompt.prompt);
                    
                    wclear(w_prompt.prompt);
                    wrefresh(w_prompt.prompt);
                    
                    derive_master_key(password, password_size, data.master_salt, old_master_key);
                }
                
                if(!verify_key(old_master_key, data.key_token)){
                    key_group old_keys;
                    get_keys(old_master_key, &old_keys);
                    
                    byte new_master_key[32];
                    
                    {
                        byte password[INPUT_LIMIT];
                        u32 password_size = get_password(password, "Enter new vault password: ", w_prompt.prompt);
                        
                        wclear(w_prompt.prompt);
                        wrefresh(w_prompt.prompt);
                        
                        derive_master_key(password, password_size, data.master_salt, new_master_key);
                    }
                    
                    key_group new_keys;
                    get_keys(new_master_key, &new_keys);
                    
                    u32 ans = yes_no_prompt("Are you sure you want to change the vault's password? (y/n)", w_prompt.prompt);
                    
                    if(ans){
                        generate_token(new_master_key, data.key_token);
                        change_vault_password(&data, &old_keys, &new_keys);
                    }
                }
                else{
                    u32 ans = yes_no_prompt("Invalid password. Do you want to try again? (y/n)", w_prompt.prompt);
                    if(ans)
                        continue;
                }
                break;
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