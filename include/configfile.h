#ifndef C_CONFIGFILE_H_H
#define C_CONFIGFILE_H_H

#include <libconfig.h>
#include "logger.h"

int configfile_init(config_t *cfg, const char *cfgfilename);
int configfile_read(config_t *cfg, const char *cfgfilename);

#endif
