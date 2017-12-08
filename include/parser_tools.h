#ifndef PARSER_TOOLS_H
#define PARSER_TOOLS_H

struct pkt_buff {
	uint8_t *mac_header;
	uint8_t *network_header;
	uint8_t *transport_header;

	uint8_t *head;
	uint8_t *data;
	uint8_t *tail;

	uint32_t len;
	uint32_t data_len;

	bool	mangled;
};

uint32_t ip_addr_invert (uint32_t ipaddr); 
void strtostr_replace(char* regex, char* replacement, char* search_in, char* write_to);
void strtodns_qfmt(char* finalrewrite, char* to_insert);
int get_len_qfmt(char* to_insert);
void pktb_change_to_nlh(struct pkt_buff *pktb, void *data);

#endif
