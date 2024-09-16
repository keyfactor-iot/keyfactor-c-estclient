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
#define _CRT_SECURE_NO_WARNINGS

#include <string.h>
#include "../include/csr.h"
#include "../include/logging.h"
#include "../include/ssl_interface.h"

/******************************************************************************/
/*************************** GLOBAL VARIABLES *********************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/* Generate a new keypair by calling the correct function in the              */
/* SSL wrapper layer                                                          */
/*                                                                            */
/* @param  - [Input] keyType: The type of key (ECC or RSA)                    */
/* @param  - [Input] keySize: The size of the key (192, 256, etc.)            */
/* @return - success: true                                                    */
/*           failure: false                                                   */
/*                                                                            */
bool generate_keypair(const char* _keyType, int _keySize) {
	bool bResult = false;

    if (0 >= _keySize) {
        log_error("%s::%s(%d) : Error in the size of the key requested.", LOG_INF);
    } else if ( (NULL == _keyType) || ( (size_t)0 == strlen(_keyType) ) ) {
        log_error("%s::%s(%d) : Error KeyType must be defined", LOG_INF);
    } else {
        log_verbose("%s::%s(%d) : Generating key pair with type %s and length %d", LOG_INF, _keyType, _keySize);
        if ( 0 == strcasecmp(_keyType, "RSA") )
            bResult = ssl_generate_rsa_keypair(_keySize);
        else if ( 0 == strcasecmp(_keyType, "ECC") )
            bResult = ssl_generate_ecc_keypair(_keySize);
        else
            log_error("%s::%s(%d) : Invalid key type %s", LOG_INF, _keyType);
    }

	return bResult;
} /* generate_keypair */

/**                                                                           */
/* Request the crypto layer to generate a new CSR using the subject provided. */
/* This request expects an ASCII CSR to be returned.                          */
/*                                                                            */
/* @param  - [Input]  : asciiSubject string with the subject line             */
/*                      e.g., CN=1234,OU=NA,O=Keyfactor,C=US                  */
/* @param  - [Output] : csrLen the # of ASCII characters in the csr           */
/* @return - success : the CSR string minus the header and footer             */
/*           failure : NULL                                                   */
/*                                                                            */
#ifdef __ALLOW_NAME_CHANGE__
char* generate_csr(const char* asciiSubject, size_t* csrLen, const bool useChallengePassword,
                   const char* challengePassword, const char* altSubjectName,
                   const bool useNameChange) {
	char* csrString = NULL;
	csrString = ssl_generate_csr(asciiSubject, csrLen, useChallengePassword, challengePassword,
                                 altSubjectName, useNameChange);
	if ( NULL == csrString )
		log_error("%s::%s(%d) : FAILED to generate CSR using Subject of %s", LOG_INF, asciiSubject);
	return csrString;
} /* generate_csr */
#else
char* generate_csr(const char* asciiSubject,
                   size_t* const csrLen, /* parasoft-suppress CERT_C-API00-a "Freeing Memory must check for NULL" */
                   const bool useChallengePassword, /* parasoft-suppress CERT_C-API00-a "Freeing Memory must check for NULL" */
                   const char* const challengePassword) /* parasoft-suppress CERT_C-API00-a "Freeing Memory must check for NULL" */
{
    char* csrString = NULL;
    if ( (NULL == asciiSubject) || ((size_t)0 == strlen(asciiSubject))) {
        log_error("%s::%s(%d) : Error, must provide an ascii subject to this function", LOG_INF);
    } else {
        csrString = ssl_generate_csr(asciiSubject, csrLen, useChallengePassword, challengePassword);
        if (NULL == csrString)
            log_error("%s::%s(%d) : FAILED to generate CSR using Subject of %s", LOG_INF, asciiSubject);
    }
    return csrString;
} /* generate_csr */
#endif

/**                                                                           */
/* Request the crypto layer to save the key to the location                   */
/* requested. The crypto layer uses the temporary key it has generated        */
/* to store into the location requested.                                      */
/*                                                                            */
/* @param  - [Input] : keyPath = the location to save the key, if NULL or     */
/*                     blank, store the encoded key appended to the cert.     */
/* @param  - [Input] : password = the password for the private key            */
/* @param  - [Input] : cert = The cert in an ASCII encoded string             */
/* @param  - [Output]: pMessage = a string array containing any messages      */
/*                     we want to pass back to the calling function           */
/* @param  - [Output]: pStatus = The status code to report back to the API    */
/* @return - success : 0                                                      */
/*           failure : an unsigned long error code                            */
/*                                                                            */
unsigned long save_key(const char* const keyPath,
                       const char* const _password, /* parasoft-suppress CERT_C-API00-a "Freeing Memory must check for NULL" */
                       const char* const cert)
{
    unsigned long err = 0;
    (void)cert;
#define ERROR_CODE_RETURN 999

    if ( (NULL == keyPath) || ( (size_t)0 == strlen(keyPath) ) ) {
        log_error("%s::%s(%d) : keyPath must be defined", LOG_INF);
        err = ERROR_CODE_RETURN;
    } else {
        err = ssl_save_cert_key(NULL, keyPath, _password, NULL);
        if (0LU != err)
            log_error("%s::%s(%d) : Failed to save certificate or key", LOG_INF);
    }

	return err;
} /* save_cert_key */

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/