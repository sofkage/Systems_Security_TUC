#define _GNU_SOURCE 
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <error.h>
#include <stdlib.h>
#include <sys/fsuid.h>

#include "sys/stat.h"

int main() 
{

	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};

	for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		} 

	}
	
	//   read a file

	file = fopen(filenames[5], "r");
	if (file == NULL) 
			printf("fopen error\n");
		else {
			fclose(file);
		}
	

	// write to files -- check for ./acmonitor -i file_0

	 char sth_to_write[4][10]={"DEN ","THELW ","ALLH ","KORWNA"};

	 file = fopen(filenames[0],"w");
	 for(i=0;i<4;i++){
	 
		if (file == NULL) 
			printf("fopen error\n");
	 	else {
	 		bytes=fwrite(sth_to_write[i],1,strlen(sth_to_write[i]),file);
	 		
	 	}
		
	}


	//uid = 1000 (getid) is malicius user -- check for ./acmonitor -m

		for(int i=0;i<10;i++){
		chmod(filenames[i], 0);
		file = fopen(filenames[i], "r");


		if(file==NULL)
			printf("fopen error\n");
	 	else 
			 fclose(file);
	
	}


/*
	int uid=2004;
		for (i = 0; i < 10; i++) {

	 if(setresuid(2004,2004,2004)){
		 error(-1,errno,"setresuid()");
	 }

	 printf("\n%u\n",getuid());

		file = fopen(filenames[i], "r");
			if(file==NULL)
				printf("fopen error\n");
	 		else 
			 	fclose(file);
	}

	*/

	

}
