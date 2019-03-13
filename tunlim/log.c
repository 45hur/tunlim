#include <sys/types.h>
#include <unistd.h>

#include "log.h"

void auditLog(const char *format, ...)
{
#ifdef DEBUG
	va_list dbgargptr;
	va_start(dbgargptr, format);
	vfprintf(stdout, format, dbgargptr);
	va_end(dbgargptr);
#endif

	char text[256] = { 0 };
	va_list argptr;
	va_start(argptr, format);
	vsprintf(text, format, argptr);
	va_end(argptr);

	FILE *fh = 0;
	char message[286] = { 0 };
	char timebuf[30] = { 0 };
	char filename[30] = { 0 };
	time_t rawtime;
	struct tm * timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(timebuf, 26, "%Y/%m/%d %H:%M:%S", timeinfo);
	sprintf(message, "{\"timestamp\":\"%s\",%s}\n", timebuf, text);
	sprintf(filename, C_MOD_LOGFILE, getpid());

	fprintf(stdout, "%s", message);

	if (fh == 0)
	{
		fh = fopen(filename, "at");
		if (!fh)
		{
			fh = fopen(filename, "wt");
		}
		if (!fh)
		{
			return;
		}
	}

	fputs(message, fh);
	fflush(fh);
	fclose(fh);
}

void debugLog(const char *format, ...)
{
#ifdef DEBUG
	va_list dbgargptr;
	va_start(dbgargptr, format);
	vfprintf(stdout, format, dbgargptr);
	va_end(dbgargptr);
#endif

	char text[256] = { 0 };
	va_list argptr;
	va_start(argptr, format);
	vsprintf(text, format, argptr);
	va_end(argptr);

	FILE *fh = 0;
	char message[286] = { 0 };
	char timebuf[30] = { 0 };
	char filename[30] = { 0 };
	time_t rawtime;
	struct tm * timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(timebuf, 26, "%Y/%m/%d %H:%M:%S", timeinfo);
	sprintf(message, "{\"timestamp\":\"%s\",%s}\n", timebuf, text);
	sprintf(filename, C_MOD_LOGDEBUGFILE, getpid());

	fprintf(stdout, "%s", message);

	if (fh == 0)
	{
		fh = fopen(filename, "at");
		if (!fh)
		{
			fh = fopen(filename, "wt");
		}
		if (!fh)
		{
			return;
		}
	}

	fputs(message, fh);
	fflush(fh);
	fclose(fh);
}