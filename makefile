all: password_manager

password_manager: src.o
	gcc src.o -ggdb -o bin/password_manager -lssl -lcrypto -lncurses -lm

src.o: src/src.c
	gcc -c src/src.c -o src.o

clean:
	rm *.o
	