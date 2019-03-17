#include "cache_domains.h"

unsigned char cache_domain_get_flags(unsigned long long flagsl, int n)
{
	unsigned char *temp = (unsigned char *)&flagsl;
	return temp[n];

	//return (flags >> (8 * n)) & 0xff; 
}

int cache_domain_compare(const void * a, const void * b)
{
	const unsigned long long ai = *(const unsigned long long*)a;
	const unsigned long long bi = *(const unsigned long long*)b;

	if (ai < bi)
	{
		return -1;
	}
	else if (ai > bi)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

cache_domain* cache_domain_init(int count)
{
	cache_domain *item = (cache_domain *)calloc(1, sizeof(cache_domain));
	if (item == NULL)
	{
		return NULL;
	}

	item->capacity = count;
	item->index = 0;
	item->searchers = 0;

	item->base = (unsigned long long *)malloc(item->capacity * sizeof(unsigned long long));

	if (item->base == NULL)
	{
		return NULL;
	}

	return item;
}

cache_domain* cache_domain_init_ex(unsigned long long *domains, short *accuracy, unsigned long long *flagsl, int count)
{
	cache_domain *item = (cache_domain *)calloc(1, sizeof(cache_domain));
	if (item == NULL)
	{
		return NULL;
	}

	item->capacity = count;
	item->index = count;
	item->searchers = 0;
	item->base = (unsigned long long *)domains;
	if (item->base == NULL)
	{
		return NULL;
	}

	return item;
}

cache_domain* cache_domain_init_ex2(unsigned long long *domains, int count)
{
	cache_domain *item = (cache_domain *)calloc(1, sizeof(cache_domain));
	if (item == NULL)
	{
		return NULL;
	}

	item->capacity = count;
	item->index = count;
	item->searchers = 0;
	item->base = (unsigned long long *)domains;
	if (item->base == NULL)
	{
		return NULL;
	}

	return item;
}



void cache_domain_destroy(cache_domain *cache)
{
	if (cache == NULL)
	{
		return;
	}

	while (cache->searchers > 0)
	{
		usleep(50000);
	}

	if (cache->base)
	{
		free(cache->base);
		cache->base = NULL;
	}
}

int cache_domain_add(cache_domain* cache, unsigned long long value)
{
	if (cache == NULL)
		return -1;

	if (cache->index >= cache->capacity)
		return -1;

	cache->base[cache->index] = value;
	cache->index++;

	return 0;
}

int cache_domain_update(cache_domain* cache, unsigned long long value)
{
	if (cache->index > cache->capacity)
		return -1;

	int position = cache->index;

	while (--position >= 0)
	{
		if (cache->base[position] == value)
		{
			break;
		}
	}

	return 0;
}

/// does not sort the other fields of the list
/// TODO: fix qsort to work with a whole struct
void cache_domain_sort(cache_domain* cache)
{
	qsort(cache->base, (size_t)cache->index, sizeof(unsigned long long), cache_domain_compare);
}

int cache_domain_contains(cache_domain* cache, unsigned long long value, domain *citem, int iscustom)
{
	if (cache == NULL)
	{
		return 0;
	}

	cache->searchers++;
	int lowerbound = 0;
	int upperbound = cache->index;
	int position;

	position = (lowerbound + upperbound) / 2;

	while ((cache->base[position] != value) && (lowerbound <= upperbound))
	{
		if (cache->base[position] > value)
		{
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
		if (iscustom == 0)
		{
			citem->crc = cache->base[position];
		}
	}

	cache->searchers--;
	return (lowerbound <= upperbound);
}