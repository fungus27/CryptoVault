all: password_manager

password_manager: main.o crypto.o data.o input.o
	gcc main.o crypto.o data.o input.o -o bin/password_manager -lssl -lcrypto -lncurses -lm -Wall -ggdb

main.o: src/main.c src/crypto.h src/data.h src/global_types.h
	gcc -c src/main.c -o main.o -Wall -ggdb

crypto.o: src/crypto.c src/crypto.h src/global_types.h
	gcc -c src/crypto.c -o crypto.o -Wall -ggdb

data.o: src/data.c src/data.h src/crypto.h src/global_types.h
	gcc -c src/data.c -o data.o -Wall -ggdb

input.o: src/input.c src/input.h src/global_types.h src/data.h
	gcc -c src/input.c -o input.o -Wall -ggdb

clean:
	rm *.o
	