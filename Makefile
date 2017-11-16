CC=gcc
CFLAGS=-Wall -g -fstack-protector-all -Wstack-protector -I ./include  

test_tree: iptools tools treebinary
	$(CC) $(CFLAGS) -lm ntree_binary.o tools.o iptools.o  test/ntree/main.c -o test/ntree/testntree

test_hashtable: hash dns_t list
	$(CC) $(CFLAGS) -lm -lcrypto hash.o dns_translation.o list.o test/hashtable/main.c -o test/hashtable/hashtable

main: interceptor dispatcher dns_t list logger configfile worker treebinary iptools tools hash
	$(CC) $(CFLAGS) interceptor.o dns_translation.o list.o  ntree_binary.o configfile.o workers.o iptools.o hash.o tools.o logger.o dispatcher.o -lm -lcrypto -lpthread -lrt -lconfig -lmnl -lnetfilter_queue test/main/main.c -o test/main/main	

interceptor:
	$(CC) $(CFLAGS) -c src/interceptor.c

configfile:
	$(CC) $(CFLAGS) -c src/configfile.c

dispatcher:
	$(CC) $(CFLAGS) -c src/dispatcher.c

worker:
	$(CC) $(CFLAGS) -c src/workers.c

list:
	$(CC) $(CFLAGS) -c  src/list.c

logger:
	$(CC) $(CFLAGS) -c src/logger.c

iptools:
	$(CC) $(CFLAGS) -c  src/iptools.c

tools:
	$(CC) $(CFLAGS) -c  src/tools.c

dns_t:
	$(CC) $(CFLAGS) -c src/dns_translation.c

hash:
	$(CC) $(CFLAGS) -c src/hash.c

treebinary:
	$(CC) $(CFLAGS) -lm -c  src/ntree_binary.c


clean:
	rm *.o
