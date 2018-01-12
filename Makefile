CC=gcc
CFLAGS=-Wall -g -fstack-protector-all -Wstack-protector -I ./include 


test_tree: iptools tools treebinary
	$(CC) $(CFLAGS) -lm ntree_binary.o tools.o iptools.o  test/ntree/main.c -o test/ntree/testntree

test_hashtable: hash dns_t list
	$(CC) $(CFLAGS) -lm -lcrypto hash.o dns_translation.o list.o test/hashtable/main.c -o test/hashtable/hashtable

all: gestiondroits dnsparser dnsrewriter parsertools interceptor controller dns_t list logger configfile worker treebinary iptools tools hash
	$(CC) $(CFLAGS) gestiondroits.o interceptor.o dns_translation.o list.o  ntree_binary.o configfile.o workers.o iptools.o hash.o tools.o logger.o controller.o dnsparser.o dnsrewriter.o parser_tools.o -lnftnl -lm -lcrypto -lpthread -lrt -lconfig  -lcap -lnetfilter_queue src/main.c -o dns-rewriter


dnsparser:
	$(CC) $(CFLAGS) -c src/dnsparser.c

dnsrewriter:
	$(CC) $(CFLAGS) -c src/dnsrewriter.c

parsertools:
	$(CC) $(CFLAGS) -c src/parser_tools.c

gestiondroits:
	$(CC) $(CFLAGS) -c src/gestiondroits.c

interceptor:
	$(CC) $(CFLAGS) -c src/interceptor.c

configfile:
	$(CC) $(CFLAGS) -c src/configfile.c

controller:
	$(CC) $(CFLAGS) -c src/controller.c

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
