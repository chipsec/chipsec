INC=-I/usr/include/python2.7

cores: 	
	cc $(INC) -c -fPIC cores.c -o cores.o
	cc cores.o -shared -o cores.so

clean:
	rm -f *.o *.so
