#pragma once

struct shared
{
	pthread_mutex_t mutex;
	int sharedResource;
};

struct shared *thread_shared;

struct ip_addr
{
	unsigned int family;
	unsigned int ipv4_sin_addr;
	unsigned __int128 ipv6_sin_addr;
};