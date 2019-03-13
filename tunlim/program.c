#include "program.h"

#include <string.h>
#include <sys/mman.h> 
#include <sys/stat.h> 
#include <sys/types.h> 
#include <unistd.h>

#include "log.h"
#include "thread_shared.h" 
#include "vector.h"

int loop = 1;
crc64_vector *statistics = 0;

int create(void **args)
{
	int err = 0;
	int fd = shm_open(C_MOD_MUTEX, O_CREAT | O_TRUNC | O_RDWR, 0600);
	if (fd == -1)
		return fd;

	if ((err = ftruncate(fd, sizeof(struct shared))) != 0)
		return err;

	thread_shared = (struct shared*)mmap(0, sizeof(struct shared), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (thread_shared == NULL)
		return -1;

	thread_shared->sharedResource = 0;

	pthread_mutexattr_t shared;
	if ((err = pthread_mutexattr_init(&shared)) != 0)
		return err;

	if ((err = pthread_mutexattr_setpshared(&shared, PTHREAD_PROCESS_SHARED)) != 0)
		return err;

	if ((err = pthread_mutex_init(&(thread_shared->mutex), &shared)) != 0)
		return err;

	createVector(&statistics, 1000);

	pthread_t thr_id;
	loop = 1;
	if ((err = pthread_create(&thr_id, NULL, &threadproc, NULL)) != 0)
		return err;

	*args = (void *)thr_id;

	debugLog("\"%s\":\"%s\"", "message", "created");

	return err;
}

int destroy(void *args)
{
	loop = 0;

	int err = 0;
	if ((err = munmap(thread_shared, sizeof(struct shared*))) == 0)
		return err;

	if ((err = shm_unlink(C_MOD_MUTEX)) == 0)
		return err;

	destroyVector(statistics);

	void *res = NULL;
	pthread_t thr_id = (pthread_t)args;
	if ((err = pthread_join(thr_id, res)) != 0)
		return err;

	debugLog("\"%s\":\"%s\"", "message", "destroyed");

	return err;
}

void* threadproc(void *arg)
{
	debugLog("\"%s\":\"%s\"", "message", "threadproc");
	int i = 0;
	while (loop)
	{
		i++;
		if (i % 5 == 0)
		{
			debugLog("\"%s\":\"%s\"", "message", "stats reset");

			pthread_mutex_lock(&(thread_shared->mutex));
			
			vectorReset(statistics);

			pthread_mutex_unlock(&(thread_shared->mutex));
		}
		vectorPrint(statistics);

		sleep(1);
	}

	return NULL;
}

int increment(char *address, int *state)
{
	pthread_mutex_lock(&(thread_shared->mutex));
	int err = 0;
	if ((err = vectorIncrement(&statistics, address)) != 0)
	{
		*state = state_none;
	}
	else
	{
		*state = vectorIsItemBlocked(statistics, address);
	}

	pthread_mutex_unlock(&(thread_shared->mutex));

	return err;
}

#ifdef NOKRES 

static int usage()
{
	fprintf(stdout, "Available commands: ");
	fprintf(stdout, "\n");
	fprintf(stdout, "exit\n");
	fprintf(stdout, "set\n");
	fprintf(stdout, "insert\n");
	fprintf(stdout, "print\n");
	return 0;
}

static int set()
{
	int err = 0;
	char command[80] = { 0 };
	fprintf(stdout, "\nEnter ip address: ");
	scanf("%79s", command);
	char ip[80] = { 0 };
	strcpy(ip, command);
	fprintf(stdout, "\nEnter value: ");
	scanf("%79s", command);

	if ((err = vectorIncrement(&statistics, command)) == 0)
	{
		fprintf(stdout, "\nAddress %s incremented.", command);
	}
	else
	{
		fprintf(stdout, "\nAddress %s not incremented.", command);
	}

	return err;
}

static int insert()
{
	int err = 0;
	char command[80] = { 0 };
	fprintf(stdout, "\nEnter ip address: ");
	scanf("%79s", command);

	if ((err = vectorAdd(&statistics, command)) == 0)
	{
		fprintf(stdout, "\nAddress %s added.", command);
	}
	else
	{
		fprintf(stdout, "\nAddress %s not added.", command);
	}

	return err;
}

static int print()
{
	int err = 0;

	vectorPrint(statistics);

	return err;
}

static int userInput()
{
	char command[80] = { 0 };
	fprintf(stdout, "\nType command:");
	scanf("%79s", command);

	if (strcmp("exit", command) == 0)
		return 0;
	else if (strcmp("set", command) == 0)
		set();
	else if (strcmp("insert", command) == 0)
		insert();
	else if (strcmp("print", command) == 0)
		print();
	else
		usage();

	return 1;
}

int main()
{
	int err = 0;
	int thr_id = 0;
	if ((err = create((void *)&thr_id)) != 0)
	{
		debugLog("\"%s\":\"%s\"", "message", "error in create");
		return err;
	}

	usage();
	while (userInput());

	if ((err = destroy((void *)&thr_id)) != 0)
	{
		debugLog("\"%s\":\"%s\"", "message", "error in destroy");
		return err;
	}

	return err;
}

#endif