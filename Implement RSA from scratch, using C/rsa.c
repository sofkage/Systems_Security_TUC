#include "rsa.h"
#include "utils.h"

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *
sieve_of_eratosthenes(int limit, int *primes_sz)
{

	size_t *primes;
	int i,j;
	int is_prime[limit];

	primes = malloc(sizeof(int)*limit);

	for (i=2;i<limit;i++)
			is_prime[i]=1;

	for (i=2;i<limit;i++)
			if (is_prime[i])
					for (j=i;i*j<limit;j++){
							is_prime[i*j]=0;

						}

	j=0;
	for (i=2; i<limit; i++){
			if (is_prime[i]){

					primes[j]=(size_t)i;
				//	printf("%lu\n",primes[j] );

					j++;

					}

	}
	*primes_sz=j;
	printf("%d\n", j);
	printf("%d\n", *primes_sz);
	return primes;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */

int
gcd(int a, int b)
{
	if (b == 0)
	return a;
else
	return gcd(b, a % b);

	/* TODO */

}


/*
 * Chooses 'e' where
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
 size_t
 choose_e(size_t primes[],int primes_sz, size_t fi_n)
 {
   int m = ( rand() % primes_sz);
   size_t e  = primes[m];

   while ((e % fi_n)==0 || gcd(e, fi_n) != 1){
     e  = (size_t)primes[( rand() % primes_sz)];
   }
   return e;
 }


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t
mod_inverse(size_t a, size_t b)
{
	a %= b;
  for (long i = 1; i < b; i++){
      if ((a * i) % b == 1)
				return i;
			}

	return -1;

}


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void)
{
	size_t*  array_primes;
	static int  primes_sz = 0;

	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;


	FILE* public_key = NULL;
	FILE* private_key = NULL;

	array_primes = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, &primes_sz);
  //printf("size = %d\n", primes_sz);

	srand(time(0));

	p = array_primes[rand() % primes_sz];
	q = array_primes[rand() % primes_sz];

	n = p*q;
	fi_n = (p-1)*(q-1);
	e = choose_e( array_primes,primes_sz,fi_n);
	d =  mod_inverse(e,fi_n );


	//printf("n=%lu\n",n );
	//printf("fn=%lu\n",fi_n );
	//printf("e=%lu\n",e );
	//printf("d=%lu\n",d );


	public_key = fopen("hpy414_public.key", "wb");
	private_key = fopen("hpy414_private.key", "wb");

	fwrite(&n, sizeof(size_t), 1, public_key);
	fwrite(&d, sizeof(size_t), 1, public_key);

	fwrite(&n, sizeof(size_t), 1, private_key);
	fwrite(&e, sizeof(size_t), 1, private_key);

	fclose(public_key);
	fclose(private_key);

}

unsigned char *read_file(char *path, unsigned long *len) {

  FILE *f;
  char *data;

  f = fopen (path, "r");

  fseek (f, 0, SEEK_END);
  *len = ftell(f);

  fseek (f, 0, SEEK_SET);
  data = malloc(*len);

  if (data) fread(data, 1, *len, f);
  fclose(f);


  return data;
}



/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_encrypt(char *input_file, char *output_file, char *key_file)
{
	FILE *output_data;
	unsigned char *in_data, *key_data;
	size_t n, d_or_e, *out_data;

	unsigned long input_len ;
	unsigned long out_len ;
	unsigned long key_len ;

	in_data 	= read_file(input_file, &input_len);
	if (in_data == 0){
		printf("Could not read file.\n");
		exit(0);
	}

	key_data	= read_file(key_file,&key_len);
	if (key_data == 0){
		printf("Could not read key file.\n");
		exit(0);
	}
	memcpy(&n, key_data, sizeof(size_t));
	memcpy(&d_or_e, key_data+sizeof(size_t), sizeof(size_t));
	//printf("key : %ld %ld\n", n, d_or_e);


	output_data = fopen(output_file,"w");
	out_len  = input_len*sizeof(size_t);
	out_data = (size_t*)malloc(out_len);



	for (int i=0; i<input_len; i++){
		out_data[i]=mod_pow((size_t)in_data[i], n, d_or_e);
	}

		fwrite(out_data, sizeof(size_t),input_len, (FILE *)output_data);

	//write_file(out_data,output_file,out_len);

	fclose(output_data);

}

size_t mod_pow(size_t base, size_t mod,size_t exponent ){
	size_t result = 1;

	for (int i=0; i<exponent; i++){
		result = (size_t)((result * base)%mod);
	}
	return result;
}

/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *input_file, char *output_file, char *key_file)
{

		FILE *output_data;

		unsigned char *in_data, *key_data, *plaintext;
		size_t n, d_or_e, *out_data;

		unsigned long input_len ;
		unsigned long out_len ;
		unsigned long key_len ;


		in_data 	= read_file(input_file, &input_len);
		if (in_data == 0){
			printf("Could not read file.\n");
			exit(0);
		}

		key_data	= read_file(key_file,&key_len);
		if (key_data == 0){
			printf("Could not read key file.\n");
			exit(0);
		}

		output_data = fopen(output_file,"wb");
		out_data = (size_t*)malloc(input_len);


		memcpy(out_data, in_data, input_len/sizeof(size_t));

		memcpy(&n, key_data, sizeof(size_t));
		memcpy(&d_or_e, key_data+sizeof(size_t), sizeof(size_t));


		plaintext = (unsigned char*)malloc((input_len/sizeof(size_t))*sizeof(unsigned char));
		size_t tmp=1;

		for (int i=0; i<input_len/sizeof(size_t); i++){
			plaintext[i]=( unsigned char)mod_pow(out_data[i], n, d_or_e);
		}

		fwrite(plaintext, sizeof(char),input_len/sizeof(size_t), (FILE *)output_data);

	fclose(output_data);

}
