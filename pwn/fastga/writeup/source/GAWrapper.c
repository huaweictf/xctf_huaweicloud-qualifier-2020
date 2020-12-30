#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main() {
  char buf[0x10] = {0};
  char GA_client_file[0x1000] = {0};
  char GA_sock_file[0x1000] = {0};
  char tmp[0x2000] = {0};
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  alarm(10);
  printf("sock num > ");
  read(0, buf, 0xf);
  long int GA_sock_num = atol(buf);
  snprintf(GA_client_file, 0xfff, "/tmp/GA_client_%ld", GA_sock_num);
  snprintf(GA_sock_file, 0xfff, "/tmp/GA_sock_%ld", GA_sock_num);
  if (!access(GA_client_file, F_OK)) {
    snprintf(tmp, 0x1fff, "rm %s", GA_client_file);
    system(tmp);
  }
  memset(GA_client_file, 0, 0x1000);
  memset(GA_sock_file, 0, 0x1000);

  snprintf(GA_client_file, 0xfff, "/tmp/GA_client_%ld", GA_sock_num);
  snprintf(GA_sock_file, 0xfff, "/tmp/GA_sock_%ld", GA_sock_num);

  char path[] = "/GAHelper";
  char *argvs[] = {
    path,
    GA_sock_file,
    GA_client_file
  };


  execve(path, argvs, NULL);

  return 0;
}
