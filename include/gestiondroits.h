#ifndef GESTION_DROITS_H
#define GESTION_DROITS_H


uid_t convert_username_to_uid(const char *username);
gid_t convert_groupname_to_gid(const char *groupname);
int set_proc_capabilities(void);
int set_proc_capabilities_after_seteuid(void);

#endif
