#ifndef TOOLS_H_INCLUDED
#define TOOLS_H_INCLUDED


uint8_t get_n_bits_from_uint32t(uint32_t base, int bitstart, int nbread);
int root_add_data_from_range_line(ntree_root *root, char line[]);
void lecture_fd_rangefile(int fd, ntree_root *root);
char* uint32_t_to_char(const uint32_t binary_number);
uint32_t uint32_t_invert(uint32_t addr);

#endif
