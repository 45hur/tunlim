#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h> 
#include <stdio.h> 
#include <string.h> 
#include <unistd.h> 


#include "crc64.h"
#include "vector.h"
#include "log.h"

int createVector(crc64_vector **vector, unsigned int capacity)
{
	if (*vector)
		return -1;

	(*vector) = (crc64_vector *)malloc(sizeof(crc64_vector));
	(*vector)->items = (crc64_vector_item *)calloc(capacity, sizeof(crc64_vector_item));

	(*vector)->capacity = capacity;
	(*vector)->count = 0;

	return 0;
}

int destroyVector(crc64_vector *vector)
{
	if (!vector)
		return -1;

	free(vector->items);
	free(vector);

	vector = NULL;

	return 0;
}

int vectorAdd(crc64_vector **vector, const char *address)
{
	crc64_vector_item *item = NULL;
	int err = 0;
	if ((err = vectorContains(*vector, address, &item)) != 0)
	{
		if (item && strcmp(address, item->name) != 0)
		{
			fprintf(stderr, "address are not qual %s %s\n", address, item->name);
		}

		return err;
	}

	if ((*vector)->count + 1 > (*vector)->capacity)
	{
		crc64_vector *newbuff = NULL;
		if ((err = createVector(&newbuff, 1000)) != 0)
		{
			return err;
		}

		crc64_vector *newvector = NULL;
		if ((err = vectorJoin(*vector, newbuff, &newvector)) != 0)
		{
			destroyVector(newbuff);
			return err;
		}

		destroyVector(newbuff);

		crc64_vector *oldvector = *vector;
		*vector = newvector;

		destroyVector(oldvector);
	}

	unsigned long long crc = crc64(0, address, strlen(address));
	(*vector)->items[(*vector)->count].checksum = crc;
	memcpy(&(*vector)->items[(*vector)->count].name, address, strlen(address));
	(*vector)->count++;

	vectorSort((*vector));

	return err;
}

int vectorContains(crc64_vector *vector, const char *address, crc64_vector_item **found)
{
	if (!vector)
		return -1;

	unsigned long long crc = crc64(0, address, strlen((const char*)address));

	unsigned int lowerbound = 0;
	unsigned int upperbound = vector->count;
	unsigned int position = 0;

	if (upperbound < 2)
	{
		if (upperbound == 1 && vector->items[position].checksum == crc)
		{
			*found = &vector->items[position];
			return 1;
		}

		return 0;
	}

	position = (lowerbound + upperbound) / 2;

	while ((vector->items[position].checksum != crc) && (lowerbound <= upperbound))
	{
		if (vector->items[position].checksum > crc)
		{
			if (position == 0)
				break;

			upperbound = position - 1;
		}
		else
		{
			lowerbound = position + 1;
		}
		position = (lowerbound + upperbound) / 2;
	}

	if (lowerbound <= upperbound)
	{
		*found = &vector->items[position];
	}

	if (position == 0)
	{
		return vector->items[position].checksum == crc;
	}

	return (lowerbound <= upperbound);
}

int vectorCompare(const void * a, const void * b)
{
	const crc64_vector_item ai = *(const crc64_vector_item*)a;
	const crc64_vector_item bi = *(const crc64_vector_item*)b;

	if (ai.checksum < bi.checksum)
	{
		return -1;
	}
	else if (ai.checksum > bi.checksum)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

int vectorJoin(crc64_vector *v1, crc64_vector *v2, crc64_vector **vout)
{
	unsigned int capacity = v1->capacity + v2->capacity;
	crc64_vector *res = NULL;
	int err = 0;

	if ((err = createVector(&res, capacity)) != 0)
	{
		return err;
	}

	res->count = v1->count + v2->count;
	size_t size = v1->count * sizeof(crc64_vector_item);
	memcpy(res->items, v1->items, size);
	memcpy(res->items + size, v2->items, v2->count * sizeof(crc64_vector_item));

	*vout = res;

	return err;
}

int vectorIncrement(crc64_vector **vector, char *address)
{
	crc64_vector_item *item = NULL;
	if (vectorContains(*vector, address, &item))
	{
		item->counter++;

		return 0;
	}

	return vectorAdd(vector, address);
}

int vectorIsItemBlocked(crc64_vector *vector, char *address)
{
	crc64_vector_item *item = NULL;
	if (vectorContains(vector, address, &item))
	{
		return item->state;
	}

	return state_none;
}

int vectorPrint(crc64_vector *vector)
{
	fprintf(stdout, "capacity=%d\tcount=%d\n", vector->capacity, vector->count);

	for (int i = 0; i < vector->count; i++)
	{
		if (vector->items[i].counter != 0)
		{
			fprintf(stdout, "%d.\t%s\t%llx\t%lld\n", i, vector->items[i].name, vector->items[i].checksum, vector->items[i].counter);
		}
	}

	return 0;
}

int vectorReset(crc64_vector *vector)
{
	for (int i = 0; i < vector->count; i++)
	{
		if (vector->items[i].counter < MAX_NUM_REQUESTS)
		{
			if (vector->items[i].state != state_none)
			{
				debugLog("\"%s\"=\"%s\",\"%s\"=\"%s\",\"%s\"=\"%s\"", "type", "state_change", "ip", vector->items[i].name, "state", "none");
				auditLog("\"%s\"=\"%s\",\"%s\"=\"%s\",\"%s\"=\"%s\"", "type", "state_change", "ip", vector->items[i].name, "state", "none");
			}
			vector->items[i].state = state_none;
			vector->items[i].counter = 0;
		}
		else
		{
			if (vector->items[i].counter >= MAX_NUM_REQUESTS * 2)
			{
				if (vector->items[i].state != state_quarantined)
				{
					debugLog("\"%s\"=\"%s\",\"%s\"=\"%s\",\"%s\"=\"%s\"", "type", "state_change", "ip", vector->items[i].name, "state", "quarantined");
					auditLog("\"%s\"=\"%s\",\"%s\"=\"%s\",\"%s\"=\"%s\"", "type", "state_change", "ip", vector->items[i].name, "state", "quarantined");
					
					vector->items[i].state = state_quarantined;
				}

				vector->items[i].counter = MAX_NUM_REQUESTS * 2;
			}
			else
			{
				if (vector->items[i].state != state_limited)
				{
					debugLog("\"%s\"=\"%s\",\"%s\"=\"%s\",\"%s\"=\"%s\"", "type", "state_change", "ip", vector->items[i].name, "state", "limited");
					auditLog("\"%s\"=\"%s\",\"%s\"=\"%s\",\"%s\"=\"%s\"", "type", "state_change", "ip", vector->items[i].name, "state", "limited");

					vector->items[i].state = state_limited;
				}

				vector->items[i].counter--;
			}
		}
	}

	return 0;
}

int vectorSort(crc64_vector *vector)
{
	qsort(vector->items, vector->count, sizeof(crc64_vector_item), vectorCompare);

	return 0;
}