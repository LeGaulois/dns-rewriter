# Presentation
Programme de réécriture DNS.

Interception basée sur les NF_QUEUES de netfilter

# Prerequis
	- Configurer les nfqueue sur iptables (ex: iptables -p udp -d 127.0.0.1 --dport 53 -j NFQUEUE --queue-num 63 --queue-bypass)

# Compilation
make main

# Lancement
./test/main/main -f general.cfg

ou avec le debug memoire
valgrind --leak-check=full --show-leak-kinds=all ./test/main/main -f general.cfg

# Logs
Logs disponibles dans ./general.<date>.log
