all:
	gcc -I. -o test aes-gcm-wrapper.c test.c -lcrypto
	gcc -I. -o example aes-gcm-wrapper.c example.c -lcrypto
