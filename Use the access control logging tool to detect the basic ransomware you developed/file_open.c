#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "sys/stat.h"



int main(int argc, char **argv){

    size_t bytes;
    FILE *file;
    
    if (argc<2){
        printf("lol\n");
        return 0;
    }
    char* dir = argv[1];
    int num = atoi(argv[2]);



    for (int i = 1 ; i<= num; i++){

        char resolved_path[1024] = {0};
        char c[4] = {0};
        char str[1000] = "To be encrypted - no.";
        realpath(dir, resolved_path);
        strcat(resolved_path, "/");
        strcat(resolved_path, "ransom_");

        sprintf(c, "%d", i);
        strcat(resolved_path, c);

        strcat(resolved_path, ".txt");

        strcat(str, c);

        file = fopen(resolved_path, "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			//chmod(filenames[i], 777);
			fwrite(str, strlen(str), 1, file);
			fclose(file);
		} 

    }

        for (int i = 1 ; i<= num; i++){
                    char junk_path[1024] = {0};


            char c[4] = {0};
            char str[1000] = "Junk File - no.";
            realpath(dir, junk_path);

            realpath(dir, junk_path);
            strcat(junk_path, "/");
            strcat(junk_path, "junk_");

            sprintf(c, "%d", i);
            strcat(junk_path, c);

            strcat(junk_path, ".junk");

            strcat(str, c);

            file = fopen(junk_path, "w+");
            if (file == NULL) 
                printf("fopen error\n");
            else {
                //chmod(filenames[i], 777);
                fwrite(str, strlen(str), 1, file);
                fclose(file);
		} 

    }


 
    return 0;
}