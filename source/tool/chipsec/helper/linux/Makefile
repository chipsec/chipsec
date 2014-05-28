INC ?= -I/usr/include/python2.7

cores: 	
	$(CC) $(INC) -c -fPIC cores.c -o cores.o
	$(CC) cores.o -shared -o cores.so

clean:
	rm -f *.o *.so
