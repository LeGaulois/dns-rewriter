#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "configfile.h"


int configfile_init(config_t *cfg, const char *cfgfilename){
    if(access(cfgfilename, F_OK)==-1){
        fprintf(stderr,"Le fichier de configuration %s \
        nexiste pas\n", cfgfilename);
        return -1;
    }
    if (access(cfgfilename, R_OK)==-1){
        fprintf(stderr,"Le fichier de configuration %s \
        nest pas accessible en lecture\n", cfgfilename);
        return -1;
    }  

    config_init(cfg);
    return 0;
}

int configfile_read(config_t *cfg, const char *cfgfilename){ 
    if(! config_read_file(cfg, cfgfilename)){ 
        fprintf(stderr,"Erreur de syntaxe dans %s (ligne %d) -> %s\n",
            config_error_file(cfg), config_error_line(cfg),
            config_error_text(cfg));
        return -1;
    }
    fprintf(stderr,"Utilisation du fichier de configuration %s\n", cfgfilename);
    return 0;
}
