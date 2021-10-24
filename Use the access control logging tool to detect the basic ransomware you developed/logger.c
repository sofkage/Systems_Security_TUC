#define _GNU_SOURCE
#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#define LOGFILE "/tmp/file_logging.log"


int getChmod(const char *path){
    struct stat ret;

    if (stat(path, &ret) == -1) {
        return -1;
    }

    return (ret.st_mode & S_IRUSR)|(ret.st_mode & S_IWUSR)|(ret.st_mode & S_IXUSR)|/*owner*/
        (ret.st_mode & S_IRGRP)|(ret.st_mode & S_IWGRP)|(ret.st_mode & S_IXGRP)|/*group*/
        (ret.st_mode & S_IROTH)|(ret.st_mode & S_IWOTH)|(ret.st_mode & S_IXOTH);/*other*/
}

unsigned char* getFingerprint(const char* filePath) {

    
    MD5_CTX context;
    unsigned char *value = (unsigned char*) malloc(MD5_DIGEST_LENGTH);


    FILE * (*original_fopen) (const char*, const char*);
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    FILE *fd = (*original_fopen)(filePath, "rb");



     if (!fd) {
            printf("%s can't be opened to calculate hash value.\n", filePath);
            value=NULL;
    }

   // printf("%s\n",filePath);
    
    long file_length;
    fseek(fd,0,SEEK_END);
    file_length=ftell(fd);
    fseek(fd,0,SEEK_SET);
    // initialisation
    MD5_Init(&context);
    //printf("%ld\n",file_length);
    MD5_Init(&context);

    unsigned char data[file_length];

    int bytes;
    
    while (( bytes = fread(data, 1, file_length, fd)) != 0) {
        MD5_Update(&context, data, bytes);
    }

    /*returns 1 for success, 0 otherwise.*/
    MD5_Final(value, &context);
    //free(value);
    fclose(fd);


    return value;
    
    
   
}

void updateLogFile(int uid, const char* filePath, int accessType, int is_action_denied) {
    
    time_t rawtime = time(NULL);
    int i;
    struct tm t = *localtime(&rawtime);
    unsigned char* hash = getFingerprint(filePath);
 
    FILE * (*original_fopen) (const char*, const char*);
    original_fopen = dlsym(RTLD_NEXT, "fopen");

    FILE *log_file = (*original_fopen)(LOGFILE, "a");
    if (log_file==NULL) printf("NULL LOGFILE\n");

    fprintf(log_file, "%u %s %d-%d-%d %02d:%02d:%02d %d %d ", uid, filePath,
            t.tm_mday,  t.tm_mon + 1, t.tm_year + 1900,  t.tm_hour, t.tm_min, t.tm_sec,
            accessType, is_action_denied);


    if (hash) {
        for (i = 0; i < MD5_DIGEST_LENGTH; i++)
            fprintf(log_file, "%02x", hash[i]);

    free(hash);
    } else {
        for (i = 0; i < MD5_DIGEST_LENGTH; i++) 
            fprintf(log_file, "%02x", 0);
    }
    fprintf(log_file,"\n");
    fclose(log_file);
}

char* getFilePath(int fp) {
    int MAXSIZE = 0xFFF;
    char proclnk[MAXSIZE];
    char *filename = (char*) malloc(MAXSIZE);
    ssize_t read;

    sprintf(proclnk, "/proc/self/fd/%d", fp);

    read = readlink(proclnk, filename, MAXSIZE);

    if (read < 0) {
        printf("failed to readlink\n");
        filename = " ";
        return filename;
    }
    filename[read] = '\0';
    return filename;
}



FILE *
fopen(const char *path, const char *mode) 
{

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);
    int is_action_denied = 0;
    int uid              = getuid();
    //int uid =2000;
    char* actualPath;   
    int accessType=0;

	original_fopen = dlsym(RTLD_NEXT, "fopen");

    if (access(path,F_OK)==0) {
        accessType = 1;     // file exists - opening
    }
    else{
        accessType = 0;     // file doesn't exist - creation
    }

	original_fopen_ret = (*original_fopen)(path, mode);


	if(original_fopen_ret == NULL ) {
            if (errno == EPERM || errno == EACCES){
                is_action_denied = 1;   //not permitted access

            }
            
            if((!strcmp(mode,"w") || !strcmp(mode,"w+") || !strcmp(mode,"a") || !strcmp(mode,"a+")))
                is_action_denied = 1;   //not permitted access
        
    }
            actualPath=realpath(path,NULL);


       
    if (chmod(actualPath, S_IRWXU | S_IWGRP | S_IWOTH) < 0) {
        is_action_denied = 1;    


    } 
    
    
    //printf("%0X\n",getChmod(actualPath));
    updateLogFile(uid, actualPath,  accessType,is_action_denied);

    free(actualPath);

	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	
    int accessType = 2;
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);


    int uid = getuid();
    int is_action_denied = 0;


	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
    fflush(stream);

 	//filepath from file descriptor
 	char* path = getFilePath(fileno(stream));  

    if (access (path, W_OK)) {
        is_action_denied = 1;     // don't have access
    }else
        is_action_denied = 0;     // have access


    updateLogFile(uid, path, accessType, is_action_denied);

    free(path);

	return original_fwrite_ret;
}



FILE * fopen64(const char * path, const char * mode){
    return fopen(path, mode);
}
