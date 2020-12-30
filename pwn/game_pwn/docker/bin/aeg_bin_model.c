#include <stdio.h>
#include <unistd.h>

#define MAX_BUF_SZIE 0x80

void init_io()
{
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
}

#define false 0
#define true 1

#define TMP_NUM_LIST
#define U_V_LIST
#define SYM_LIST
#define SYM_MID_LIST
#define RESULT_LIST

#define STACK_SIZE

#define EQUATION(v) (TMP_NUM##v SYM##v ptr[U_V##v])
#define CHECK(v0, v1, r) ((EQUATION(v0) SYM_MID##r EQUATION(v1)) == RESULT##r)
#define IF_FALSE(v0, v1, r) CHECK(v0, v1, r) == false

int vul_func(int equ_num)
{
	char buff[STACK_SIZE];
	unsigned char *ptr = (unsigned char *)&equ_num;
	if (IF_FALSE(0, 1, 0))
		goto equ_fail;
	if (IF_FALSE(2, 3, 1))
		goto equ_fail;
	if (IF_FALSE(4, 5, 2))
		goto equ_fail;
	if (IF_FALSE(6, 7, 3))
		goto equ_fail;
	read(0, buff, STACK_SIZE+MAX_BUF_SZIE*3);
	return 1;
equ_fail:
	return 0;
}

int main(int argc, char **argv)
{
	init_io();
	alarm(6);
	if (argc < 2)
		exit(0);
	return vul_func(atoi(argv[1]));
}