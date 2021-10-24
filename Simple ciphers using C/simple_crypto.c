#include<stdio.h>
#include<string.h>
#include<ctype.h>
#include "simple_crypto.h"


//  				OTP

char* otp_encrypt(char* input, char* xor_key){

  static char encrypted_otp[200];
  int i=0;

  printf("[OTP] encrypted: ");

  for(i=0;input[i] != '\0';i++){
    encrypted_otp[i]=input[i]^xor_key[i];

    if(!(isprint(encrypted_otp[i]))){
      printf("$");
    }
    else {
      printf("%c",encrypted_otp[i]);
    }
  }

  printf("\n");

  return encrypted_otp;

}


void otp_decrypt(char* cipher, char xor_key[]){

  char decrypted_otp[100];
  int i=0;

  printf("[OTP] decrypted: ");
  for(i=0;cipher[i]!='\0';i++){
    decrypted_otp[i]=cipher[i]^xor_key[i];
    printf("%c",decrypted_otp[i]);

  }
printf("\n");
}

//                       Caesar's cipher

	char* caesar_encrypt(char* input, int key ){

		static char encrypted_caesars[100];
		int i;


		for(i = 0; input[i] != '\0'; ++i){

			if( input[i] >= '0' &&  input[i] <= '9'){
				if(input[i]+key > '9'){
          encrypted_caesars[i] = (input[i]+key-48)%10+'A';
        }else{
          encrypted_caesars[i]=(input[i]+key-48)%10+'0';
			  }

			}
      else if( input[i] >= 'A' &&  input[i] <= 'Z'){
				if(input[i]+key > 'Z'){
          encrypted_caesars[i] =(input[i]+key-65)%26+'a';
        }else{
          encrypted_caesars[i]=(input[i]+key-65)%26+'A';
			  }
      }
        else if( input[i] >= 'a' &&  input[i] <= 'z'){
  				if(input[i]+key > 'z'){
            encrypted_caesars[i] = (input[i]+key-97)%26+'0';
          }else{
            encrypted_caesars[i]=(input[i]+key-97)%26+'a';
  			  }
        }


	}
  printf("[Caesars] encrypted: %s\n", encrypted_caesars);

  return(encrypted_caesars);
}

	void caesar_decrypt(char cipher[], int key ){

		int i;
    static char decrypted_caesars[100];

    for(i = 0; cipher[i] != '\0'; ++i){  //end

			if( cipher[i] >= '0' &&  cipher[i] <= '9'){
				if(cipher[i]-key < '0'){
          decrypted_caesars[i] = (cipher[i]-key-48+26)%26+'a';
        }else{
          decrypted_caesars[i]=(cipher[i]-key-48+10)%10+'0';
			  }

			}
      else if( cipher[i] >= 'A' &&  cipher[i] <= 'Z'){
				if(cipher[i]-key < 'A'){
          decrypted_caesars[i] = (cipher[i]-key-65+10)%10+'0';
        }else{
          decrypted_caesars[i]=(cipher[i]-key-65+26)%26+'A';
			  }
      }
        else if( cipher[i] >= 'a' &&  cipher[i] <= 'z'){
  				if(cipher[i]-key <'a'){
            decrypted_caesars[i] = (cipher[i]-key-97+26)%26+'A';
          }else{
            decrypted_caesars[i]=(cipher[i]-key-97+26)%26+'a';
  			  }
        }

	}

	printf("[Caesars] decrypted: %s\n", decrypted_caesars);

}


// 						viginere

void vigenere_encrypt_decrypt(char* input, char* key ){


  int inputLen = strlen(input), keyLen = strlen(key), j,i;
  char newKey[inputLen], encrypted_vigenere[inputLen], decrypted_vigenere[inputLen];

  //generating new key
  for(i = 0, j = 0; i < inputLen; ++i, ++j){
      if(j == keyLen)
          j = 0;
      newKey[i] = key[j];
  }
  newKey[i] = '\0';

  //encryption
  for(i = 0; i < inputLen; ++i)
      encrypted_vigenere[i] = ((input[i] + newKey[i]) % 26) + 'A';

  encrypted_vigenere[i] = '\0';

  //decryption
  for(i = 0; i < inputLen; ++i)
      decrypted_vigenere[i] = (((encrypted_vigenere[i] - newKey[i]) + 26) % 26) + 'A';

  decrypted_vigenere[i] = '\0';


  printf("[Vigenere] encrypted: %s\n", encrypted_vigenere);
  printf("[Vigenere] decrypted: %s\n", decrypted_vigenere);

}
