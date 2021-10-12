void caesar();
void otp();
void vigenere();


char* otp_encrypt(char* input, char* xor_key);
void otp_decrypt(char* cipher, char xor_key[]);

char* caesar_encrypt (char* input, int key );
void caesar_decrypt(char* input, int key );

void vigenere_encrypt_decrypt(char* input, char* key );
