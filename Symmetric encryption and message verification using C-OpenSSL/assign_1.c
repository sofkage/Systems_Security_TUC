#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16

//define the aes_ecb acccording to the bits mode. If 128 then EVP_aes_128_ecb, else EVP_aes_256_ecb
#define AES_ECB(bits) (bits == 128) ? EVP_aes_128_ecb() : EVP_aes_256_ecb()


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t);
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
void encrypt(unsigned char *, int, unsigned char *, unsigned char *,
    unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *,
    unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);
unsigned char *read_file(char *, unsigned long *);
void write_file(char *, unsigned char *, unsigned long);


/* TODO Declare your function prototypes here... */



/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits"
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password,
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
void keygen(unsigned char *password, unsigned char *key, unsigned char *iv, int bit_mode){

  /*derives a key and IV from various parameters
    type AES_ECB
    message digest EVP_sha1
  */

  EVP_BytesToKey(AES_ECB(bit_mode), EVP_sha1(), NULL, password,	strlen((const char *) password), 1, key, iv);

}


/*
 * Encrypts the data
 */
void encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
              unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{
  EVP_CIPHER_CTX *context;
	int len, ciphertext_len; //The ciphertext may be bigger than the plaintext due to padding

  //creates a cipher context.
	context = EVP_CIPHER_CTX_new();

  /*set up cipher context ctx for encryption with cipher type from ENGINE impl */
	EVP_EncryptInit_ex(context, AES_ECB(bit_mode), NULL, key, NULL);

  //encrypts inl bytes from the buffer in and writes the encrypted version to out
	EVP_EncryptUpdate(context, ciphertext, &len, plaintext, plaintext_len);

  //EVP_EncryptFinal_ex() encrypts the "final" data, that is any data that remains in a partial block
  ciphertext_len = len;
  EVP_EncryptFinal_ex(context, ciphertext + len, &len);

  ciphertext_len += len;
  print_hex(ciphertext, ciphertext_len);
  //free
	EVP_CIPHER_CTX_free(context);

}


/*
 * Decrypts the data and returns the plaintext size
 */
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext, int bit_mode)
{

  EVP_CIPHER_CTX *context;
	int plaintext_len, len;
	plaintext_len = 0;

  //creates a cipher context.
  context = EVP_CIPHER_CTX_new();

  //decryption operation
	EVP_DecryptInit_ex(context, AES_ECB(bit_mode), NULL, key, NULL);
	EVP_DecryptUpdate(context, plaintext, &len, ciphertext, ciphertext_len);


  //EVP_DecryptFinal() will return an error code if padding is enabled and the final block is not correctly formatted
	plaintext_len = len;
	EVP_DecryptFinal_ex(context, ciphertext + len, &len);

	plaintext_len += len;
  print_string(plaintext, plaintext_len);

  //free
	EVP_CIPHER_CTX_free(context);

	return plaintext_len;
}


/*
 * Generates a CMAC
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key,
    unsigned char *cmac, int bit_mode)
{
  CMAC_CTX *context = NULL;
	size_t out_len;

  /* allocates a new CMAC_CTX object, initializes the
  embedded EVP_CIPHER_CTX object, and marks the object itself as uninitialized. */
	context = CMAC_CTX_new();

  /*selects the given block cipher for use by ctx
    if bit_mode = 128 then 128/8=16
    if bit_mode = 256 then 256/8=32*/
	CMAC_Init(context, key, bit_mode / 8, AES_ECB(bit_mode), NULL);

  /*processes data_len bytes of input data pointed to by data*/
	CMAC_Update(context, data, data_len);

  /*stores the length of the message authentication
  code in bytes, which equals the cipher block size, into *out_len*/
	CMAC_Final(context, cmac, &out_len);

  //free
	CMAC_CTX_free(context);
}


/* verify */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	int verify;
	verify = 0;

  /*compares memory blocks.
  returns TRUE if the CMAC is successfully verified and
  stores the plaintext in an appropriate file.
  Otherwise, it just returns FALSE. */
  if(memcmp((const char *)cmac1, (const char *)cmac2, BLOCK_SIZE)==0)  verify = 1;
  else verify = 0;
	return verify;
}

// function to read and write the input/output files

void write_file(char *path, unsigned char *data, unsigned long len) {
  FILE *f;
  f = fopen (path, "wb");
  fwrite(data, 1, len, f);
}

unsigned char *read_file(char *path, unsigned long *len) {

  FILE *f;
  unsigned char *data;

  f = fopen (path, "rb");

  fseek (f, 0, SEEK_END);
  *len = ftell(f);

  fseek (f, 0, SEEK_SET);
  data = malloc(*len);

  if (data) fread(data, 1, *len, f);
  fclose(f);

  return data;
}

/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */
  unsigned char *in;
	unsigned char *out;
  unsigned long in_len;
	unsigned long out_len;
	unsigned char cmac[BLOCK_SIZE];
	unsigned char key[256];
  unsigned char iv[256];


	/* Init arguments */
	input_file   = NULL;
	output_file  = NULL;
	password     = NULL;
	bit_mode     = -1;
	op_mode      = -1;
  in           = NULL;
  out          = NULL;
  in_len       = 0;
  out_len      = 0;


	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);

  if (input_file != NULL)
		in = read_file(input_file, &in_len);



	/* Keygen from password */
  keygen(password, key, iv, bit_mode);

  if(op_mode == 0){   	/* encrypt */
    out_len = in_len - (in_len % BLOCK_SIZE) + BLOCK_SIZE;
    out = malloc(out_len);
    encrypt(in, in_len, key, iv, out, bit_mode);

  }else if (op_mode ==1){  /* decrypt */
    out = malloc(in_len);
    out_len = decrypt(in, in_len, key, iv, out,bit_mode);

  }else if (op_mode ==2){  	/* sign */
    out_len = in_len - (in_len % BLOCK_SIZE) + 2*BLOCK_SIZE;
    out = malloc(out_len);
    encrypt(in, in_len, key, iv, out, bit_mode);
    gen_cmac(in, in_len, key, out + (out_len - BLOCK_SIZE), bit_mode);

  }else if (op_mode==3){ /* verify */
      out = malloc(in_len);
      out_len = decrypt(in, in_len - BLOCK_SIZE, key, iv, out,bit_mode);

      gen_cmac(out, out_len, key, cmac, bit_mode);

      if (verify_cmac(cmac, in + (in_len - BLOCK_SIZE)) == 1){
          printf("Verified - TRUE\n");
      }else{
        printf("Not Verified - FALSE\n");
        free(in);
        free(out);
        free(input_file);
        free(output_file);
        free(password);
        return 0;
      }
    }


  if (out_len)
    write_file(output_file, out, out_len);



	/* Clean up */
  free(in);
  free(out);
	free(input_file);
	free(output_file);
	free(password);


	/* END */
	return 0;
}
