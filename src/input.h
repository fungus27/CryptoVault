#ifndef INPUT_H
#define INPUT_H

#include <ncurses.h>

#include "global_types.h"
#include "data.h"

void copy_to_clipboard(char* input);

i32 get_path(char* path, char* prompt, WINDOW* w_prompt);

u32 get_unique_login(login_data* data, byte* login, char* prompt, WINDOW* w_prompt);
u32 get_password(byte* password, char* prompt, WINDOW* w_prompt);

u32 get_uint(char* prompt, WINDOW* w_prompt);

void random_password(unsigned int password_size, byte* password);

#endif //INPUT_H
