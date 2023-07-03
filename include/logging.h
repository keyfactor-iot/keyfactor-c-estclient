/******************************************************************************/
/* Copyright 2023 Keyfactor                                                   */
/* Licensed under the Apache License, Version 2.0 (the "License"); you may    */
/* not use this file except in compliance with the License.  You may obtain a */
/* copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless */
/* required by applicable law or agreed to in writing, software distributed   */
/* under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES   */
/* OR CONDITIONS OF ANY KIND, either express or implied. See the License for  */
/* thespecific language governing permissions and limitations under the       */
/* License.                                                                   */
/******************************************************************************/

#ifndef __LOGGING_H__
#define __LOGGING_H__

#include <stdbool.h>

/**************************************************************************/
/************************* GLOBAL DEFINES *********************************/
/**************************************************************************/
#define LOG_INF __FILE__, __FUNCTION__, __LINE__

/**************************************************************************/
/******************* GLOBAL FUNCTION PROTOTYPES ***************************/
/**************************************************************************/
void log_error(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));
void log_warn(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));
void log_info(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));
void log_verbose(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));
void log_debug(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));
void log_trace(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));

void log_set_trace(bool param);
void log_set_debug(bool param);
void log_set_verbosity(bool param);
void log_set_info(bool param);
void log_set_warn(bool param);
void log_set_error(bool param);
void log_set_off(bool param);

bool is_log_debug( void );
bool is_log_trace( void );

#endif /* __LOGGING_H__ */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/