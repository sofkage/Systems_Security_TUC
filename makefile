demo: demo.o simple_crypto.o
	gcc -o demo demo.o simple_crypto.o

demo.o : demo.c simple_crypto.h
	gcc -c demo.c


simple_crypto.c: simple_crypto.c simple_crypto.h
	gcc -c simple_crypto.c

clean:
	rm all demo.o
