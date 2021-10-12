**** README ****

This file contains of the following parts:

1) simple_crypto.h
Consists of the declarations of the used functions. These are:

void caesar();
void otp();
void vigenere();
char* otp_encrypt(char* input, char* xor_key);
void otp_decrypt(char* cipher, char xor_key[]);
char* caesar_encrypt (char* input, int key );
void caesar_decrypt(char* input, int key );
void vigenere_encrypt_decrypt(char* input, char* key );


2) simple_crypto.c
Consists of the implementation of the functions. All of the cryptographic algorithms
are fully implemented. Explaination of implementation:

---OTP---
Performs XOR between the plaintext and the key generated from /dev/urandom.
Whenever the XOR outcome is a non printable character, is being replaced
with a '$'.

---Ceasar's cipher---
For encryption, we need to consider that the sets '0-9', 'A-Z' and 'a-z' are a single set.
So, we define the borders of each set and calculating the encrypted message by using the ASCII
code too. For example, we have the following lines from the function:

              if( input[i] >= '0' &&  input[i] <= '9'){
                if(input[i]+key > '9'){
                  encrypted_caesars[i] = (input[i]+key-48)%10+'A';
                }else{
                  encrypted_caesars[i]=(input[i]+key-48)%10+'0';
                }
              }

In this case, the input character is a number. We calculate the outcome of the encryption
by checking the value of the input + the key. According to the set order, if the output
is >9 the next set is 'A-Z', else we stay at '0-9'. This is defined by the base we choose
('A' or '0').Also, %10 is referring to the 10-number-set we have as input. 48 is '0', the
start of the set we have as input.

---Vigenere's cipher---

We use modulo as above, but in this case we use only uppercase. The key needs to be repeated
to match the size of the plain text.

Note: The user's input is considered valid.

3) demo.c
This file consists of the main function, as well as three void functions for each
algorithm which are called in it. In these functions, the input and the key (wherever
is necessary) are passed as arguments to the functions in simple_crypto.c.

4) makefile
A makefile to compile the library.
