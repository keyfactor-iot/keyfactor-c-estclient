/******************************************************************************/
/* Copyright 2021 Keyfactor                                                   */
/* Licensed under the Apache License, Version 2.0 (the "License"); you may    */
/* not use this file except in compliance with the License.  You may obtain a */
/* copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless */
/* required by applicable law or agreed to in writing, software distributed   */
/* under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES   */
/* OR CONDITIONS OF ANY KIND, either express or implied. See the License for  */
/* thespecific language governing permissions and limitations under the       */
/* License.                                                                   */
/******************************************************************************/

#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "../include/logging.h"

#define LOG_HEAD_SIZE 50
#define LOG_LEVEL_SIZE 10
#define MAX_LOG_SIZE 1024 + LOG_HEAD_SIZE + LOG_LEVEL_SIZE

#define ERRORLVL   "[ERROR]  "
#define WARNLVL    "[WARNING]"
#define INFOLVL    "[INFO]   "
#define VERBOSELVL "[VERBOSE]"
#define DEBUGLVL   "[DEBUG]  "
#define TRACELVL   "[TRACE]  "

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/
static bool _trace = false;
static bool _debug = false;
static bool _verbose = false;
static bool _info = true; /* default logging level */
static bool _warn = true;
static bool _error = true; 
static char logFormat[LOG_HEAD_SIZE + MAX_LOG_SIZE + LOG_LEVEL_SIZE];
static char timeBuf[LOG_HEAD_SIZE];

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/*	locally defined function to format the log level with date & message      */
/*	@param  char *buf = place to store the formatted message                  */
/*	@param  const char *msgFormat = message to print                          */
/*	@param  const char *logLevel = the log level of the message               */
/*	@return none                                                              */
/*                                                                            */
static inline void get_log_format(char* buf, const char* msgFormat,	const char* logLevel)
{
	time_t t = time(NULL);
	struct tm* tm = gmtime(&t);
	(void)strftime(timeBuf, LOG_HEAD_SIZE, "%Y-%m-%d %H:%M:%S", tm);
	(void)snprintf(buf, MAX_LOG_SIZE, "[%s] - %s - %s\n", timeBuf, logLevel, msgFormat);
} /* get_log_format */

/**                                                                           */
/*  local-only function to print a message                                    */
/*	@returns none                                                             */
/*                                                                            */
static void log_me( const char* fmt, ... )
{
	get_log_format(logFormat, fmt, "[LOGGING]");

	va_list args;
	va_start(args, fmt);
	vprintf(logFormat, args);
	va_end(args);
} /* log_me */

/******************************************************************************/
/************************ GLOBAL FUNCTION DEFINITIONS *************************/
/******************************************************************************/
/**                                                                           */
/*  @fn is_log_verbose                                                        */
/*	@brief check the current state of the verbose logging level               */
/*	@param none                                                               */
/*	@returns true if verbose level is enabled, false otherwise                */
/*                                                                            */
bool is_log_verbose( void )
{
	return _verbose;
} /* is_log_verbose */

/**                                                                           */
/*  @fn is_log_trace                                                          */
/*	@brief check the current state of the trace logging level                 */
/*	@param none                                                               */
/*	@returns true if trace level is enabled, false otherwise                  */
/*                                                                            */
bool is_log_trace( void )
{
	return _trace;
} /* is_log_trace */

/**                                                                           */
/*  @fn is_log_debug                                                          */
/*	@brief check the current state of the debug logging level                 */
/*	@param none                                                               */
/*	@returns true if debug level is enabled, false otherwise                  */
/*                                                                            */
bool is_log_debug( void )
{
	return _debug;
} /* is_log_debug */

/**                                                                           */
/*  @fn is_log_info                                                           */
/*	@brief check the current state of the info logging level                  */
/*	@param none                                                               */
/*	@returns true if info level is enabled, false otherwise                   */
/*                                                                            */
bool is_log_info( void )
{
	return _info;
} /* is_log_info */

/**                                                                           */
/* @fn is_log_warn                                                            */
/* @brief check the current state of the warning logging level                */
/* @param none                                                                */
/* @returns true if the warning level is enabled, false otherwise             */
/*                                                                            */
bool is_log_warn( void )
{
	return _warn;
} /* is_log_warn */

/**                                                                           */
/*  @fn is_log_error                                                          */
/*	@brief check the current state of the error logging level                 */
/*	@param none                                                               */
/*	@returns true if error level is enabled, false otherwise                  */
/*                                                                            */
bool is_log_error( void )
{
	return _error;
} /* is_log_error */

/**                                                                           */
/*  @fn is_log_off                                                            */
/*	@brief check if logging is off                                            */
/*	@param none                                                               */
/*	@returns true if the error level is off, false otherwise                  */
/*                                                                            */
bool is_log_off( void )
{
	return !_error;
} /* is_log_off */


/**                                                                           */
/*  @fn log_error                                                             */
/*	@brief Print a message if the error logging level is enabled              */
/*	@returns none                                                             */
/*                                                                            */
void log_error(const char* fmt, ...)
{
	if (_error) {
		get_log_format(logFormat, fmt, ERRORLVL);

		va_list args;
		va_start(args, fmt);
		vfprintf(stderr, logFormat, args);
		va_end(args);
	}
} /* log_error */

/**                                                                           */
/*  @fn log_warn                                                              */
/*	@brief Print a message if the info logging level is enabled               */
/*	@returns none                                                             */
/*                                                                            */
void log_warn(const char* fmt, ...)
{
	if(_warn) {
		get_log_format(logFormat, fmt, WARNLVL);

		va_list args;
		va_start(args, fmt);
		vfprintf(stderr, logFormat, args);
		va_end(args);
	}
} /* log_warn */

/**                                                                           */
/*  @fn log_info                                                              */
/*	@brief Print a message if the info logging level is enabled               */
/*	@returns none                                                             */
/*                                                                            */
void log_info(const char* fmt, ...)
{
	if(_info) {
		get_log_format(logFormat, fmt, INFOLVL);

		va_list args;
		va_start(args, fmt);
		vfprintf(stderr, logFormat, args);
		va_end(args);
	}
} /* log_info */

/**                                                                           */
/*  @fn log_verbose                                                           */
/*	@brief Print a message if the verbose logging level is enabled            */
/*	@returns none                                                             */
/*                                                                            */
void log_verbose(const char* fmt, ...)
{
	if(_verbose) {
		get_log_format(logFormat, fmt, VERBOSELVL);
		va_list args;
		va_start(args, fmt);
		vfprintf(stderr, logFormat, args);
		va_end(args);
	}
} /* log_verbose */

/**                                                                           */
/*  @fn log_debug                                                             */
/*	@brief Print a message if the debug logging level is enabled              */
/*	@returns none                                                             */
/*                                                                            */
void log_debug(const char* fmt, ...)
{
	if(_debug) {
		get_log_format(logFormat, fmt, DEBUGLVL);
		va_list args;
		va_start(args, fmt);
		vfprintf(stderr, logFormat, args);
		va_end(args);
	}
} /* log_debug */

/**                                                                           */ 
/*  @fn log_trace                                                             */
/*	@brief Print a message if the trace logging level is enabled              */
/*	@returns none                                                             */
/*                                                                            */
void log_trace(const char* fmt, ...)
{
	if(_trace) {
		get_log_format(logFormat, fmt, TRACELVL);
		va_list args;
		va_start(args, fmt);
		vfprintf(stderr, logFormat, args);
		va_end(args);
	}
} /* log_trace */

/**                                                                           */
/*  @fn log_set_trace                                                         */
/*	@brief Turn on the trace & all lower logging levels                       */
/*	@returns none                                                             */
/*                                                                            */
void log_set_trace(bool param)
{
	log_me( "%s::%s(%d) : Setting logging level to trace.", LOG_INF );
	_trace = param;
	_debug = param;
	_verbose = param;
	_info = param;
	_warn = param;
	_error = param;
} /* log_set_trace */

/**                                                                           */
/*  @fn log_set_debug                                                         */
/*	@brief Turn on the debug & all lower logging levels                       */
/*	@returns none                                                             */
/*                                                                            */
void log_set_debug(bool param)
{
	log_me( "%s::%s(%d) : Setting logging level to debug.", LOG_INF );
	_trace = !param;
	_debug = param;
	_verbose = param;
	_info = param;
	_warn = param;
	_error = param;
} /* log_set_debug */

/**                                                                           */ 
/*  @fn log_set_verbosity                                                     */
/*	@brief Turn on the verbose & all lower logging levels                     */
/*	@returns none                                                             */
/*                                                                            */
void log_set_verbosity(bool param)
{
	log_me( "%s::%s(%d) : Setting logging level to verbose.", LOG_INF );
	_trace = !param;
	_debug = !param;
	_verbose = param;
	_info = param;
	_warn = param;
	_error = param;
} /* log_set_verbosity */

/**                                                                           */
/*  @fn log_set_info                                                          */
/*	@brief Turn on the info & all lower logging levels                        */
/*	@returns none                                                             */
/*                                                                            */
void log_set_info(bool param)
{
	log_me( "%s::%s(%d) : Setting logging level to info.", LOG_INF );
	_trace = !param;
	_debug = !param;
	_verbose = !param;
	_info = param;
	_warn = param;
	_error = param;
} /* log_set_info */

/**                                                                           */
/* @fn log_set_warn                                                           */
/* @breif Turn on the warning logging level & all lower logging levels        */
/* @returns none                                                              */
/*                                                                            */
void log_set_warn(bool param)
{
	log_me("%s::%s(%d) : Setting logging level to warning.", LOG_INF);
	_trace = !param;
	_debug = !param;
	_verbose = !param;
	_info = !param;
	_warn = param;
	_error = param;
} /* log_set_warn */

/**                                                                           */
/*  @fn log_set_error                                                         */
/*	@brief Turn on the error logging level                                    */
/*	@returns none                                                             */
/*                                                                            */
void log_set_error(bool param)
{
	log_me( "%s::%s(%d) : Setting logging level to error.", LOG_INF );
	_trace = !param;
	_debug = !param;
	_verbose = !param;
	_info = !param;
	_warn = !param;
	_error = param;
} /* log_set_error */

/**                                                                           */
/*  @fn log_set_off                                                           */
/*	@brief Turn off all further logging                                       */
/*	@returns none                                                             */
/*                                                                            */
void log_set_off(bool param)
{
	log_me( "%s::%s(%d) : Turning off all logging.", LOG_INF );
	_trace = !param;
	_debug = !param;
	_verbose = !param;
	_info = !param;
	_warn = !param;
	_error = !param;
} /* log_set_off */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/