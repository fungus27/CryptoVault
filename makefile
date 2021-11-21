all: password_manager

password_manager: main.o crypto.o data.o
	gcc main.o crypto.o data.o -o bin/password_manager -lssl -lcrypto -lncurses -lm -Wall -ggdb

main.o: src/main.c src/crypto.h src/data.h src/global_types.h
	gcc -c src/main.c -o main.o -Wall -ggdb

crypto.o: src/crypto.c src/crypto.h src/global_types.h
	gcc -c src/crypto.c -o crypto.o -Wall -ggdb

data.o: src/data.c src/data.h src/crypto.h src/global_types.h
	gcc -c src/data.c -o data.o -Wall -ggdb

clean:
	rm *.o
	