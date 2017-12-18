#include <stdio.h>
#include <stdlib.h>




/*
* Fonction
*
*/
void lecture_fd(int fd){
    char buffer[1024];
    int i=0, nb=0;
    static char cache[1024];
    static int j=0;
    
    do{
        nb = read(fd,(void*)(buffer),1023);
            
        if(nb>0){
            if(nb<1023){
                buffer[nb]='\0';
            }
                       
            for(i=0; i<nb ;i++){
                cache[j] = buffer[i];
                
                if(cache[j] == '\n'){
                    cache[j+1]='\0';
                    fprintf(stdout, "%s",cache);
                    
                    /*
                    * TODO
                    * A ce niveau la on appelle 
                    * notre fonction de parsing
                    */
                    j=0;
                    continue;
                }
                j++;  
            }
        }
        else if(nb==0){
            break;
        }
        else{
            fprintf(stderr,"\nErreur: %s.\n", strerror(errno));
            break;
        }
        
    }while(1);
}
