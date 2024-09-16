/******************************************************************************/
/* Copyright 2023 Keyfactor                                                   */
/* Licensed under the Apache License, Version 2.0 (the "License"); you may    */
/* not use this file except in compliance with the License.  You may obtain a */
/* copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless */
/* required by applicable law or agreed to in writing, software distributed   */
/* under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES   */
/* OR CONDITIONS OF ANY KIND, either express or implied. See the License for  */
/* the specific language governing permissions and limitations under the      */
/* License.                                                                   */
/******************************************************************************/

#ifndef __CSR_H__
#define __CSR_H__

#include <stdbool.h>

/**************************************************************************/
/******************* GLOBAL FUNCTION PROTOTYPES ***************************/
/**************************************************************************/
bool generate_keypair(const char* keyType, int keySize);
#ifdef __ALLOW_NAME_CHANGE__
char* generate_csr(const char* asciiSubject, size_t* csrLen, const bool useChallengePassword,
                   const char* challengePassword, const char* altSubjectName,
                   const bool useNameChange);
#else
char* generate_csr(const char* asciiSubject, size_t* const csrLen, const bool useChallengePassword,
                   const char* const challengePassword);
#endif
unsigned long save_key(const char* const keyPath,
                       const char* const _password,
                       const char* const cert);
#endif /* __CSR_H__ */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/