#pragma once

#ifndef LOG_H
#define LOG_H

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "thread_shared.h"

#define C_MOD_MUTEX "mutex.whalebone.kres.module\0"
#define C_MOD_LOGFILE "/var/log/whalebone/whalebone.log\0"
#define C_MOD_LOGDEBUG "/var/log/whalebone/debug.log\0"
#define C_MOD_LOGAUDIT "/var/log/whalebone/audit.log\0"

void debugLog(const char *format, ...);
void fileLog(const char *format, ...);
void auditLog(const char *format, ...);

#endif