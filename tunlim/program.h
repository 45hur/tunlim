#pragma once
 
#include <fcntl.h> 

#include "thread_shared.h"

int ftruncate(int fd, off_t length);

int create(void **args);
int destroy();
int init();

void* threadproc(void *arg);
int increment(char *address, int *state);
int search(const char * querieddomain, struct ip_addr * userIpAddress, const char * userIpAddressString, int rrtype, char * originaldomain, char * logmessage);
int explode(char * domainToFind, struct ip_addr * userIpAddress, const char * userIpAddressString, int rrtype);