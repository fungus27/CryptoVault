all: password_manager

password_manager: src.o
	gcc src.o -o bin/password_manager -lssl -lcrypto -lncurses -lm -Wall -ggdb

src.o: src/src.c
	gcc -c src/src.c -o src.o -ggdb

clean:
	rm *.o
	