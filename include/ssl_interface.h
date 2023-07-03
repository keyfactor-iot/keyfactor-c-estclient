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
#ifndef __OPENSSL_WRAPPER_H__
#define __OPENSSL_WRAPPER_H__

#include <stdbool.h>
#include <stddef.h>

/**************************************************************************/
/******************* GLOBAL FUNCTION PROTOTYPES ***************************/
/**************************************************************************/
bool ssl_generate_rsa_keypair(int keySize);
bool ssl_generate_ecc_keypair(int keySize);
#ifdef __ALLOW_NAME_CHANGE__
char* ssl_generate_csr(const char* asciiSubject, size_t* csrLen, const bool useChallengePassword, const char* pw,
                       const char* asciiAltSubject, const bool useNameChange);
#else
char* ssl_generate_csr(const char* asciiSubject, size_t* csrLen, const bool useChallengePassword, const char* pw);
#endif
unsigned long ssl_save_cert_key(const char* storePath, const char* keyPath,	const char* password, const char* cert);
void ssl_init(void);
void ssl_cleanup(void);
char* ssl_convert_P7_to_pem(const unsigned char* pkcs7Der, const size_t len, bool addSubjects);
char* ssl_get_subject(const char* fileLocation, const unsigned int maxSubjectLen);
#endif /* OPENSSL_WRAPPER_H */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/