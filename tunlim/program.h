#pragma once
 
#include <fcntl.h> 

int ftruncate(int fd, off_t length);

int create(void **args);
int destroy();

void* threadproc(void *arg);
int increment(char *address, int *state);