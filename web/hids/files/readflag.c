#include <stdio.h>
#include <unistd.h>
int main()
{
   FILE *fp = NULL;
   char buff[255];

   fp = fopen("/flag", "r");
   printf("Please wait 90s...\n");
   sleep(90);
   fscanf(fp, "%s", buff);
   printf("%s\n", buff );

}