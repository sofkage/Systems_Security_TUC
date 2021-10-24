#define _GNU_SOURCE
#include <time.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define LOGFILE "/tmp/file_logging.log"


typedef struct entry{
    int uid;
    int mod_counter;
    int action_denied;
    int access_type;
    int ready;
    char array_of_files[8][1024];
    struct entry * next;
}entry;

entry * user_list;
entry * mod_file;
entry * tmp;
entry * denied_accesses;
entry * entry_helper;


void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./acmonitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}
entry * is_in_list( entry * _entry, int key){
	 entry * tmp = _entry;
    while(tmp != NULL){
        if(tmp->uid == key)
            return tmp;
        
        tmp = tmp->next;
    }
    return NULL;
}


void 
list_unauthorized_accesses(FILE *log)
{
	denied_accesses = NULL;
	entry_helper = NULL;
    int uid;
    char file[1024];
    int day, month, year, hour, min, sec;
    int access_type;
    int action_denied;
    unsigned char fingerprint[MD5_DIGEST_LENGTH];
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    int exists_in_array;
    int i;

    while ((read = getline(&line, &len, log)) != EOF) {

        sscanf(line, "%d %s %d-%d-%d %02d:%02d:%02d %d %d",  &uid, file, &day, &month, &year, &hour, &min,&sec, &access_type, &action_denied);

        		if( action_denied==1 && denied_accesses == NULL ){
                    entry_helper = ( entry *)malloc(sizeof( entry));
                    entry_helper->uid = uid;
                    entry_helper->access_type = access_type;
                    entry_helper->action_denied = action_denied;

                    memcpy(entry_helper->array_of_files[0], file, 1024);
                    entry_helper->next = NULL;
                    denied_accesses = entry_helper;

                    }else if(action_denied==1){
                        if((entry_helper = is_in_list(denied_accesses, uid)) == NULL){          
                         entry * entry_new = ( entry *)malloc(sizeof( entry));

                            while(denied_accesses->next != NULL){
                                denied_accesses = denied_accesses->next;
                            }

                            denied_accesses->next = entry_new;
                            entry_new->uid = uid;
                            entry_new->access_type = access_type;
                            entry_new->action_denied = 1;
                            entry_new->next = NULL;

                            memcpy(entry_new->array_of_files[0], file, 1024);	


    		            }else{
                            exists_in_array = 0;
                            if(entry_helper->ready==0){

                                for(int i=0;i<8;i++){
                                    if(!strcmp(file, entry_helper->array_of_files[i])){
                                        exists_in_array = 1;
                                    }
                                }
                                if(exists_in_array==0){
                                    entry_helper->action_denied++;
                                    memcpy(entry_helper->array_of_files[entry_helper->action_denied-1], file, 1024);
                                }
                            }

                            if(entry_helper->action_denied == 8)
                                entry_helper->ready = 1;
                            
                            }
                        }
        }

            entry_helper = denied_accesses;

            while(entry_helper != NULL){
                
                if(entry_helper->ready)
                    printf("Found malicious user with uid: %d\n", entry_helper->uid);
                
                entry_helper = entry_helper->next;
            }
            while(denied_accesses != NULL){
                entry_helper = denied_accesses->next;
                free(denied_accesses);
                denied_accesses = entry_helper;
            }
  return;

}


void
list_file_modifications(FILE *log, char* file_to_scan)
{

    int uid;
    char filePath[1024];
    char * file ;
    int day, month, year, hour, min, sec;
    int access_type;
    int action_denied;
    char fingerprint1[MD5_DIGEST_LENGTH*2+1] = {0};
    char fingerprint2[MD5_DIGEST_LENGTH*2+1] = {0};    
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    int i;


    while ((read = getline(&line, &len, log)) != EOF) {

        fscanf(log, "%d %s %d-%d-%d %02d:%02d:%02d %d %d %s",  &uid, filePath, &day, &month, &year, &hour, &min,&sec, &access_type, &action_denied,fingerprint1);

        char *last_token = strrchr(filePath, '/');

        if (last_token != NULL) {
            file = last_token +1;
        }    

        if (!strcmp(file, file_to_scan) && strcmp(fingerprint1,fingerprint2) && action_denied == 0 ) {// users have access to the file
   
            memcpy(fingerprint2, fingerprint1, MD5_DIGEST_LENGTH*2+1); //init fingerprint2
                   
            if(mod_file == NULL){
                tmp = ( entry *)malloc(sizeof( entry));
				tmp->uid = uid;
				tmp->mod_counter = 1;
				tmp->next = NULL;
				mod_file = tmp;

            }else{
                tmp = is_in_list(mod_file,uid);

                if(tmp == NULL){
                    
                        tmp = mod_file;
                        while(tmp->next != NULL){
                                tmp = tmp->next;
                        }
                            tmp->next = ( entry *)malloc(sizeof( entry));
                            tmp->next->uid = uid;
                            tmp->next->mod_counter = 1;
                            tmp->next->next = NULL;
                }

                        tmp->mod_counter++;

            }
                
        }
        
    }

    tmp = mod_file;

	while(tmp != NULL){
		printf("%d  %d\n", tmp->uid,tmp->mod_counter);
		tmp = tmp->next;
	}
	while(mod_file != NULL){
		tmp = mod_file->next;
		free(mod_file);
		mod_file = tmp;
	}


    //printf("%02hhx -> hash ",fingerprint1);
    //printf("\n%02hhx -> hash ",fingerprint2);

   
   fclose(log);
    return;
}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE* log ;
     char* file_to_scan;

	user_list = NULL;

	if (argc < 2)
		usage();

    log = fopen(LOGFILE, "r");
        if (log == NULL) {
            printf("Error opening log file \n");
            return -1;
    }


	while ((ch = getopt(argc, argv, "hmi")) != -1) {
		switch (ch) {		
		case 'i':
            file_to_scan = argv[2];
			list_file_modifications(log,file_to_scan);
			break;
		case 'm':      
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	argc -= optind;
	argv += optind;	
	
	return 0;
}
