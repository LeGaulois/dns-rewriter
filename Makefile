CC=gcc
CFLAGS=-Wall -g -fstack-protector-all -Wstack-protector -I ./include  

test_tree: iptools tools treebinary
	$(CC) $(CFLAGS) -lm ntree_binary.o tools.o iptools.o  test/ntree/main.c -o test/ntree/testntree
	
list:
	$(CC) $(CFLAGS) -c  src/list.c

iptools:
	$(CC) $(CFLAGS) -c  src/iptools.c

tools:
	$(CC) $(CFLAGS) -c  src/tools.c


treebinary:
	$(CC) $(CFLAGS) -lm -c  src/ntree_binary.c


clean:
	rm *.o
