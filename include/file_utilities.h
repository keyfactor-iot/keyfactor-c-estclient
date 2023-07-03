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

#ifndef __FILE_UTILITIES_H__
#define __FILE_UTILITIES_H__

#include <stddef.h>

/**************************************************************************/
/******************* GLOBAL FUNCTION PROTOTYPES ***************************/
/**************************************************************************/
bool file_exists( const char *fileName );
bool create_file( const char *file );
int backup_file(const char* file);
int replace_file(const char* file, const char* contents, long len, bool backup);
int read_file_bytes(const char* srcPath, unsigned char** pFileBytes, size_t* fileLen);

#endif /* __FILE_UTILITIES_H__ */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/