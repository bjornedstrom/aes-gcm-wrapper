all:
	gcc -Wall -Wstrict-prototypes -I. -o test aes-gcm-wrapper.c test.c -lcrypto
	gcc -Wall -Wstrict-prototypes -I. -o example aes-gcm-wrapper.c example.c -lcrypto
