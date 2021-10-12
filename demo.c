#include<string.h>
#include<stdio.h>
#include "simple_crypto.h"

int main(){

  otp();
  caesar();
  vigenere();
  return 0;
}


void otp(){

  char input[100];
  char key[100];
  FILE* random_key;

  printf("[OTP] input: ");
  scanf("%s", input);

  random_key = fopen("/dev/urandom", "r");
  fgets(key,100,(FILE*)random_key);

	otp_decrypt((char*)otp_encrypt(input,key),key);

  fclose(random_key);

}

void caesar(){

  char input[100];
  int key;
  printf("[Caesars] input: ");
  scanf("%s", input);
  printf("[Caesars] key: ");
  scanf("%d", &key);

  caesar_decrypt(caesar_encrypt(input, key),key);

  }


void vigenere(){

  char input[100],key[100];
  printf("[Vigenere] input: ");
  scanf("%s", input);
  printf("[Vigenere] key: ");
  scanf("%s", key);

  vigenere_encrypt_decrypt(input, key);
}
