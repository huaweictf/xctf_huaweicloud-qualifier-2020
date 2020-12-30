#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <errno.h>
#include "cJSON/cJSON.h"

static const char* base64Table="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char base64TableMap[]={\
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,\
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,\
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,\
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,\
    -1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,\
    18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,\
    28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,\
    44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,-1,-1,-1,\
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,\
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,\
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,\
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,\
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,\
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,\
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,\
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};

int base64_encode(const char* input, int inputLen, char* output){
    int i,n,state,pos;
    n=state=pos=0;
    for(i=0;i<inputLen;i++){
        switch(pos){
        case 0:
            state=(input[i]&0xFC)>>2;
            output[n++]=base64Table[state];
            state=(input[i]&0x3)<<4;
            pos=1;
            break;
        case 1:
            state|=((input[i]&0xF0)>>4);
            output[n++]=base64Table[state];
            state=(input[i]&0xF)<<2;
            pos=2;
            break;
        case 2:
            state|=((input[i]&0xC0)>>6);
            output[n++]=base64Table[state];
            state=input[i]&0x3F;
            output[n++]=base64Table[state];
            pos=0;
            break;
        }
    }
    if(pos==1){
        output[n++]=base64Table[state];
        output[n++]='=';
        output[n++]='=';
    }
    else if(pos==2){
        output[n++]=base64Table[state];
        output[n++]='=';
    }
    return n;
}

int base64_decode(const char* input,int inputLen,char* output){
    int pos,i,n;
    char cch,t;
    n=pos=0;
    for(i=0;i<inputLen;i++){
        cch=input[i];
        t=base64TableMap[cch];
        if(cch=='=') break;
            switch(pos){
            case 0:
                output[n]=(t<<2)&0xff;
                pos=1;
                break;
            case 1:
                output[n]=(output[n]|((t&0x30)>>4))&0xff;
                n++;
                output[n]=((t&0xf)<<4)&0xff;
                pos=2;
                break;
            case 2:
                output[n]=(output[n]|((t&0x3c)>>2))&0xff;
                n++;
                output[n]=((t&0x3)<<6)&0xff;
                pos=3;
                break;
            case 3:
                output[n]=(output[n]|t)&0xff;
                n++;
                pos=0;
                break;
            }
    }
    return n;
}

int GA_sock = -1;

void menu() {
  printf("[1] show GA info\n"
         "[2] GA read file\n"
         "[3] GA write file\n"
         "[4] GA execve\n"
         "[5] Exit\n");
}

size_t get_size_t() {
  char buf[0x10] = "\x00";
  read(0, buf, 0xf);
  return (size_t)atol(buf);
}

void PrintJson(cJSON *root, size_t level) {
  if (level >= 8) {
    for (size_t j = 0; j < level; j ++) {
      printf("  ");
    }
    printf("%s\n", root->string);
    return;
  }
  if (root->type == cJSON_Object) {
    for (size_t j = 0; j < level; j ++) {
      printf("  ");
    }
    printf("%s {\n", root->string);
    for (int i = 0; i < cJSON_GetArraySize(root); i ++) {
      cJSON *item = cJSON_GetArrayItem(root, i);
      PrintJson(item, level + 1);
    }
    for (size_t j = 0; j < level; j ++) {
      printf("  ");
    }
    printf("}\n");
  }
  else if (root->type == cJSON_Array) {
    for (size_t j = 0; j < level; j ++) {
      printf("  ");
    }
    printf("%s [\n", root->string);
    for (int j = 0; j < cJSON_GetArraySize(root); j ++) {
      PrintJson(cJSON_GetArrayItem(root, j), level + 1);
    }
    for (size_t j = 0; j < level; j ++) {
      printf("  ");
    }
    printf("]\n");
  }
  else {
    for (size_t j = 0; j < level; j ++) {
      printf("  ");
    }
    char *tmp = cJSON_Print(root);
    if (tmp != NULL) {
      printf("%s: %s\n", root->string, tmp);
      free(tmp);
    }
  }
}

cJSON *ParseJson(char *src) {
  return cJSON_Parse(src);
}

char *SendCommandReadRet(char *command) {
  char tmp[0x1000] = {0};
  if (command[strlen(command) - 1] == '\n') {
    write(GA_sock, command, strlen(command));
  }
  else {
    write(GA_sock, command, strlen(command));
    write(GA_sock, "\n", 1);
  }
  int readed = read(GA_sock, tmp, 0xfff);
  if (readed < 0) {
    while (errno == EAGAIN && readed < 0) {
      usleep(100000);
      readed = read(GA_sock, tmp, 0xfff);
    }
    if (errno != EAGAIN) {
      exit(1);
    }
  }
  if (tmp[readed - 1] == '\n') {
    char *ret = (char *)calloc(strlen(tmp) + 1, 1);
    memcpy(ret, tmp, strlen(tmp));
    return ret;
  }
  char *ret = (char *)malloc(strlen(tmp) + 1);
  memset(ret, 0, strlen(tmp) + 1);
  memcpy(ret, tmp, strlen(tmp));
  while (tmp[readed - 1] != '\n') {
    memset(tmp, 0, 0xfff);
    int n = read(GA_sock, tmp, 0xfff);
    if (n < 0) {
      while (errno == EAGAIN && readed < 0) {
        usleep(100000);
        n = read(GA_sock, tmp, 0xfff);
      }
      if (errno != EAGAIN) {
        exit(1);
      }
      break;
    }
    ret = (char *)realloc(ret, strlen(ret) + strlen(tmp) + 1);
    memset(ret + strlen(ret), 0, strlen(tmp) + 1);
    memcpy(ret + strlen(ret), tmp, strlen(tmp));
  }
  if (ret[strlen(ret) - 1] != '\n') {
    free(ret);
    return NULL;
  }
  return ret;
}

void show_GA_Info() {
  char cmd[] = "{\"execute\": \"guest-info\"}";
  char *ret = SendCommandReadRet(cmd);
  if (ret == NULL) {
    return;
  }
  cJSON *root = ParseJson(ret);
  if (root != NULL) {
    PrintJson(root, 0);
    cJSON_Delete(root);
  }
}

int GA_open_file(char *path, char *mode) {
  cJSON *root = cJSON_CreateObject();
  cJSON *arguments = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "execute", cJSON_CreateString("guest-file-open"));
  cJSON_AddItemToObject(arguments, "path", cJSON_CreateString(path));
  cJSON_AddItemToObject(arguments, "mode", cJSON_CreateString(mode));
  cJSON_AddItemToObject(root, "arguments", arguments);
  char *tmp = cJSON_Print(root);
  if (tmp == NULL) {
    return -1;
  }
  char *handle_info = SendCommandReadRet(tmp);
  if (handle_info == NULL) {
    cJSON_Delete(root);
    free(tmp);
    return -1;
  }
  cJSON *handle_info_root = cJSON_Parse(handle_info);
  if (handle_info_root == NULL) {
    cJSON_Delete(root);
    free(tmp);
    free(handle_info);
    return -1;
  }
  cJSON *handle_obj = NULL;
  for (int i = 0; i < cJSON_GetArraySize(handle_info_root); i ++) {
    if (!strcmp(cJSON_GetArrayItem(handle_info_root, i)->string, "return")) {
      handle_obj = cJSON_GetArrayItem(handle_info_root, i);
    }
  }
  if (handle_obj == NULL) {
    cJSON_Delete(root);
    cJSON_Delete(handle_info_root);
    free(tmp);
    free(handle_info);
    return -1;
  }
  int handle_id = handle_obj->valueint;
  cJSON_Delete(root);
  cJSON_Delete(handle_info_root);
  free(tmp);
  free(handle_info);
  return handle_id;
}

void GA_close_file(int handle_id) {
  cJSON *close_root = cJSON_CreateObject();
  cJSON *close_arguments = cJSON_CreateObject();
  cJSON_AddItemToObject(close_root, "execute", cJSON_CreateString("guest-file-close"));
  cJSON_AddItemToObject(close_arguments, "handle", cJSON_CreateNumber(handle_id));
  cJSON_AddItemToObject(close_root, "arguments", close_arguments);
  char *tmp = cJSON_Print(close_root);
  if (tmp == NULL) {
    cJSON_Delete(close_root);
    return;
  }
  SendCommandReadRet(tmp);
  cJSON_Delete(close_root);
}

void GA_read_file() {
  printf("file path size > ");
  size_t path_size = get_size_t();
  if (path_size > 0x1000 || path_size < 1) {
    return;
  }
  char *file_path = (char *)calloc(path_size, 1);
  if (file_path == NULL) {
    exit(0);
  }
  printf("file path > ");
  read(0, file_path, path_size);
  if (strlen(file_path) > 0) {
    if(file_path[strlen(file_path) - 1] == '\n') {
      file_path[strlen(file_path) - 1] = '\x00';
    }
  }
  file_path[path_size - 1] = 0;

  char mode[] = "r";
  int handle_id = GA_open_file(file_path, mode);
  if (handle_id == -1) {
    return;
  }

  cJSON *read_root = cJSON_CreateObject();
  cJSON *read_arguments = cJSON_CreateObject();
  cJSON_AddItemToObject(read_root, "execute", cJSON_CreateString("guest-file-read"));
  cJSON_AddItemToObject(read_arguments, "handle", cJSON_CreateNumber(handle_id));
  cJSON_AddItemToObject(read_arguments, "count", cJSON_CreateNumber(0x1000));
  cJSON_AddItemToObject(read_root, "arguments", read_arguments);
  char *tmp = cJSON_Print(read_root);
  if (tmp == NULL) {
    cJSON_Delete(read_root);
    free(file_path);
    return;
  }
  char *read_info = SendCommandReadRet(tmp);
  if (read_info == NULL) {
    cJSON_Delete(read_root);
    free(file_path);
    return;
  }

  cJSON *read_info_root = cJSON_Parse(read_info);
  if (read_info_root == NULL) {
    cJSON_Delete(read_root);
    free(tmp);
    free(read_info);
    free(file_path);
    return;
  }
  cJSON *return_obj = NULL;
  for (int i = 0; i < cJSON_GetArraySize(read_info_root); i ++) {
    if (!strcmp(cJSON_GetArrayItem(read_info_root, i)->string, "return")) {
      return_obj = cJSON_GetArrayItem(read_info_root, i);
    }
  }
  if (return_obj == NULL) {
    free(tmp);
    free(read_info);
    free(file_path);
    cJSON_Delete(read_root);
    cJSON_Delete(read_info_root);
    return;
  }
  char *buf_b64 = NULL;
  size_t count = 0;
  for (int i = 0; i < cJSON_GetArraySize(return_obj); i ++) {
    if (!strcmp(cJSON_GetArrayItem(return_obj, i)->string, "buf-b64")) {
      buf_b64 = cJSON_GetArrayItem(return_obj, i)->valuestring;
    }
    else if (!strcmp(cJSON_GetArrayItem(return_obj, i)->string, "count")) {
      count = cJSON_GetArrayItem(return_obj, i)->valueint;
    }
  }
  char b64dec_buf[0x1000] = {0};
  if (buf_b64 != NULL) {
    base64_decode(buf_b64, strlen(buf_b64), b64dec_buf);
    printf( "content: %s\n", b64dec_buf);
  }

  GA_close_file(handle_id);

  free(tmp);
  free(read_info);
  free(file_path);
  cJSON_Delete(read_root);
  cJSON_Delete(read_info_root);
}

void GA_write_file() {
  printf("file path size > ");
  size_t path_size = get_size_t();
  if (path_size > 0x1000 || path_size < 1) {
    return;
  }
  char *file_path = (char *)calloc(path_size, 1);
  if (file_path == NULL) {
    exit(0);
  }
  printf("file path > ");
  read(0, file_path, path_size);
  if (strlen(file_path) > 0) {
    if(file_path[strlen(file_path) - 1] == '\n') {
      file_path[strlen(file_path) - 1] = '\x00';
    }
  }
  file_path[path_size - 1] = 0;
  printf("content size > ");
  size_t content_size = get_size_t();
  if (content_size > 0x1000 || content_size < 1) {
    free(file_path);
    return;
  }
  char *content = (char *)calloc(content_size, 1);
  if (content == NULL) {
    exit(0);
  }
  printf("conent > ");
  read(0, content, content_size);
  char *content_b64 = (char *)calloc(content_size * 2 + 0x10, 1);
  base64_encode(content, content_size, content_b64);
  free(content);

  char mode[] = "w";
  int handle_id = GA_open_file(file_path, mode);
  if (handle_id == -1) {
    return;
  }

  cJSON *write_root = cJSON_CreateObject();
  cJSON *write_arguments = cJSON_CreateObject();
  cJSON_AddItemToObject(write_root, "execute", cJSON_CreateString("guest-file-write"));
  cJSON_AddItemToObject(write_arguments, "handle", cJSON_CreateNumber(handle_id));
  cJSON_AddItemToObject(write_arguments, "buf-b64", cJSON_CreateString(content_b64));
  cJSON_AddItemToObject(write_arguments, "count", cJSON_CreateNumber(content_size));
  cJSON_AddItemToObject(write_root, "arguments", write_arguments);
  char *tmp = cJSON_Print(write_root);
  if (tmp == NULL) {
    cJSON_Delete(write_root);
    free(file_path);
    return;
  }
  char *write_info = SendCommandReadRet(tmp);
  if (write_info == NULL) {
    cJSON_Delete(write_root);
    free(tmp);
    free(file_path);
    return;
  }

  cJSON *write_info_root = cJSON_Parse(write_info);
  if (write_info_root == NULL) {
    cJSON_Delete(write_root);
    free(tmp);
    free(write_info);
    free(file_path);
    return;
  }

  PrintJson(write_info_root, 0);

  GA_close_file(handle_id);

  free(tmp);
  free(write_info);
  free(file_path);
  cJSON_Delete(write_root);
  cJSON_Delete(write_info_root);

}

void GA_execve() {
  char buf[0x10] = {0};
  printf("file path size > ");
  size_t path_size = get_size_t();
  if (path_size > 0x1000 || path_size < 1) {
    return;
  }
  char *file_path = (char *)calloc(path_size, 1);
  if (file_path == NULL) {
    exit(0);
  }
  printf("file path > ");
  read(0, file_path, path_size);
  if (strlen(file_path) > 0) {
    if(file_path[strlen(file_path) - 1] == '\n') {
      file_path[strlen(file_path) - 1] = '\x00';
    }
  }
  file_path[path_size - 1] = 0;
  printf("argv count > ");
  size_t g_argv_cnt = get_size_t();
  if (g_argv_cnt > 0x10) {
    free(file_path);
    return;
  }
  char **g_argvs = NULL;
  if (g_argv_cnt > 0) {
    g_argvs = (char **)calloc(sizeof(char *), g_argv_cnt);
    if (g_argvs == NULL) {
      exit(0);
    }
    for (size_t i = 0; i < g_argv_cnt; i ++) {
      printf("argv %ld size > ", i);
      size_t argv_size = get_size_t();
      if (argv_size > 0x100 || argv_size < 1) {
        for (size_t j = 0; j < i; j ++) {
          free(g_argvs[j]);
        }
        free(file_path);
        free(g_argvs);
        return;
      }
      g_argvs[i] = (char *)calloc(argv_size, 1);
      if (g_argvs[i] == NULL) {
        exit(0);
      }
      printf("argv %ld content > ", i);
      read(0, g_argvs[i], argv_size - 1);
      if (strlen(g_argvs[i]) > 1) {
        if (g_argvs[i][strlen(g_argvs[i]) - 1] == '\n') {
          g_argvs[i][strlen(g_argvs[i]) - 1] = '\x00';
        }
      }
    }
  }
  size_t output = 0;
  printf("output ? y/n");
  memset(buf, 0, 0x10);
  read(0, buf, 2);
  if (buf[0] == 'y') {
    output = 1;
  }
  cJSON *execve_root = cJSON_CreateObject();
  cJSON *execve_arguments = cJSON_CreateObject();
  cJSON_AddItemToObject(execve_root, "execute", cJSON_CreateString("guest-exec"));
  cJSON_AddItemToObject(execve_arguments, "path", cJSON_CreateString(file_path));
  if (g_argv_cnt > 0) {
    cJSON *execve_arguments_args = cJSON_CreateArray();
    for (size_t i = 0; i < g_argv_cnt; i ++) {
      cJSON_AddItemToArray(execve_arguments_args, cJSON_CreateString(g_argvs[i]));
    }
    cJSON_AddItemToObject(execve_arguments, "arg", execve_arguments_args);
  }
  if (output == 1) {
    cJSON_AddItemToObject(execve_arguments, "capture-output", cJSON_CreateBool(1));
  }
  cJSON_AddItemToObject(execve_root, "arguments", execve_arguments);

  char *tmp = cJSON_Print(execve_root);
  if (tmp == NULL) {
    cJSON_Delete(execve_root);
    free(file_path);
    if (g_argvs != NULL) {
      for (size_t i = 0; i < g_argv_cnt; i ++) {
        free(g_argvs[i]);
      }
      free(g_argvs);
    }
    return;
  }
  char *execve_info = SendCommandReadRet(tmp);

  cJSON *execve_info_root = cJSON_Parse(execve_info);
  if (execve_info_root == NULL) {
    free(tmp);
    free(file_path);
    cJSON_Delete(execve_root);
    free(file_path);
    if (g_argvs != NULL) {
      for (size_t i = 0; i < g_argv_cnt; i ++) {
        free(g_argvs[i]);
      }
      free(g_argvs);
    }
    return;
  }

  PrintJson(execve_info_root, 0);

  free(tmp);
  free(file_path);
  cJSON_Delete(execve_root);
  cJSON_Delete(execve_info_root);
  if (g_argvs != NULL) {
    for (size_t i = 0; i < g_argv_cnt; i ++) {
      free(g_argvs[i]);
    }
    free(g_argvs);
  }
  return;
}

void __attribute__ ((constructor)) __init() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  alarm(60);
}

int main(int argc, char **argv) {
  char *client_path = argv[2];
  if (argc != 3) {
    return 1;
  }
  GA_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (GA_sock < 0) {
    return 1;
  }
  if (fcntl(GA_sock, F_SETFL, O_NONBLOCK) == -1) {
    exit(errno);
  }
  struct sockaddr_un client, serun;
  memset(&client, 0, sizeof(client));
  client.sun_family = AF_UNIX;
  strcpy(client.sun_path, client_path);
  int len = offsetof(struct sockaddr_un, sun_path) + strlen(client.sun_path);
  unlink(client.sun_path);
  if (bind(GA_sock, (struct sockaddr *)&client, len) < 0) {
    //printf("last error %s\n", strerror(errno));
    exit(1);
  }
  if (GA_sock < 0) {
    return 1;
  }

  memset(&serun, 0, sizeof(serun));
  serun.sun_family = AF_UNIX;
  memcpy(serun.sun_path, argv[1], strlen(argv[1]) > sizeof(serun.sun_path) - 1? sizeof(serun.sun_path) - 1: strlen(argv[1]));
  len = offsetof(struct sockaddr_un, sun_path) + strlen(serun.sun_path);
  if (connect(GA_sock, (struct sockaddr *)&serun, len) < 0) {
    return 1;
  }
  while (1) {
    menu();
    size_t choice = get_size_t();
    switch (choice) {
      case 1:
        show_GA_Info();
        break;
      case 2:
        GA_read_file();
        break;
      case 3:
        GA_write_file();
        break;
      case 4:
        GA_execve();
        break;
      case 5:
        remove(argv[2]);
        exit(0);
        break;
    }
  }
  return 0;
}
