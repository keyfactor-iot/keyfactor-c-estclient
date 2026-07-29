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
/* suppress the deprecated error message for now */ //:TODO Update for OpenSSL 3.0
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include "../../include/ssl_interface.h"
#include "../../include/logging.h"
#include "../../include/file_utilities.h"
#include "../../lib/include/base64.h"

#include <openssl/opensslv.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h> /* for GENERAL_NAME etc. */
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/rsa.h>

/******************************************************************************/
/***************************** LOCAL DEFINES  *********************************/
/******************************************************************************/

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    void RSA_get0_key(const RSA* r, const BIGNUM** n, const BIGNUM** e, const BIGNUM**d) {
        if(n != NULL) {
            *n = r->n;
        }
        if(e != NULL) {
            *e = r->e;
        }
        if(d != NULL) {
            *d = r->d;
        }
    }
#endif /* OPENSSL_VERSION_NUMBER */


#ifndef SSL_SUCCESS
	#define SSL_SUCCESS 1
#endif

#ifndef X509_VERSION_3
    #define X509_VERSION_3 2
#endif

#define RSA_DEFAULT_EXP 65537
#define MAX_CSR_SIZE 4096

#define ID_CMC_CHANGESUBJECTNAME  "1.3.6.1.5.5.7.7.36"

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/
X509_EXTENSION* ext = NULL;
STACK_OF(X509_EXTENSION*) extStack = NULL;
ASN1_SEQUENCE_ANY* seq = NULL;

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/

/* This keypair is for temporary storage in memory.                           */
/* Once the certificate is received from the platform, this gets stored to    */
/* The file system                                                            */
EVP_PKEY* keyPair = NULL;

/* The following keys must be locally global & freed upon exiting the program */
/* If these keys are freed, then the global variable above (keyPair) becomes  */
/* corrupted.  Therefore, we must make these global variables.                */
RSA* newRsa = NULL;
EC_KEY* newEcc = NULL;


/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/* Look through the subject to decode the subject's value                     */
/* e.g., if subject is CN=12345,O=Keyfactor then this function is passed      */
/* the portion after the equals sign.  The first time it is called, it will   */
/* receive 12345,O=Keyfactor.  It will return 12345                           */
/* The next time it is called it will be passed Keyfactor & return Keyfactor. */
/*                                                                            */
/* If an ascii escaped string is encountered it parses the value accordingly. */
/* e.g., if domain\\user is sent, the subject is converted to domain\user     */
/*                                                                            */
/* If an ascii escaped hex value is encontered it parses the value accordingly*/
/* e.g., if \\3F  then the value ? is returned.                               */
/*                                                                            */
/* @param  - [Input] : subject = a portion of the full subject after a key    */
/*                               i.e., it starts with a value for the key     */
/* @param  - [Ouput] : buf = string containing the value                      */
/* @return - success : how far into the subject string we found a subject     */
/*					   separator                                              */
/*         - failure : -1                                                     */
/*                                                                            */
static int read_subject_value(const char* subject, char* buf)
{
	int subjLen = strlen(subject);
	int subInd = 0;
	int bufInd = 0;
	char c = ' ';
	char escaped[1] = {' '};
	unsigned int hexHi, hexLo;

	bool done = false;
	bool hasError = false;

	while(!done && !hasError && subInd < subjLen) {
		c = subject[subInd];
		switch(c) {
		case '\\':
			if(sscanf(&subject[subInd], "\\%1[\" #+,;<=>\\]", escaped) == 1) {
				if(buf) {
					buf[bufInd++] = escaped[0];
				}
				subInd += 2;
			} else if(sscanf(&subject[subInd], "\\%1x%1x", &hexHi, &hexLo) == 2) {
				if(buf) {
					buf[bufInd++] = (char)((hexHi << 4) | hexLo);
				}
				subInd += 3;
			} else {
				hasError = true;
			}
			break;
		case ',':
			done = true;
			break;
		default:
			if(buf) {
				buf[bufInd++] = c;
			}
			++subInd;
			break;
		}
	}

	if(buf) buf[bufInd] = '\0';

	return hasError ? -1 : subInd;
} /* read_subject_value */

/**                                                                           */
/* Return a pointer to the first non-space element in the string.  The string */
/* MAY be modified by this function by adding a NULL ('\0') terminator        */
/* inside the string.  This null terminator may be before the null terminator */
/* of the original string.                                                    */
/*                                                                            */
/* for example, both of these may happen:                                     */
/*   string = " I have spaces before and after me      "\0                    */
/* Here is what happens this function does:                                   */
/*                                                                            */
/* sring = " I have spaces before and after me      "\0                       */
/*           ^                                ^ is replaced with \0           */
/*           |                                                                */
/*            - beg (returned value)                                          */
/*                                                                            */
/* NOTE: This doesn't ADD any dynamically allocated memory                    */
/*       so you MUST NOT DEALLOCATE the returned value.  The returned         */
/*       value is at a minimum, a subset pointing inside the original data    */
/*       structure.  At a maximum it is the same pointer.                     */
/*                                                                            */
/* @param  - [Input/Output] : string = the string to parse                    */
/* @param  - [Input] : the length of the string                               */
/* @return - none                                                             */
/*                                                                            */
static char* strip_blanks(char* string)
{
	char* beg = string;  /* Copy the pointer so we can advance */
	char* end = string + strlen(string) - 1; /* Point to the string's end */

	/* Remove any leading spaces */
	while (isspace((unsigned char)*beg)) {
		beg++;
	}

	/* beg now points to the first non whitespace character */
	/* now find the last non-whitespace character */
	while (isspace((unsigned char)*end) && (end != (beg-1)) ) {
		end--;
	}

	/* Null terminate one after the last non-whitespace character */
	end[1] = '\0';

	return beg;
} /* strip_blanks */

/**                                                                           */
/* Populate the correct subject of the certificate request                    */
/*                                                                            */
/* @param  - [Input/Output] nm = The name to modify                           */
/* @param  - [Input] key = the subject key to modify                          */
/* @param  - [Input] value = the value to populate                            */
/* @return - none                                                             */
/*                                                                            */
static void populate_subject(X509_NAME* nm, char* key, char* value)
{
    unsigned char* byte = (unsigned char*) value;
	if ( 0 == (strcasecmp(key,"C")) ) {
		log_trace("%s::%s(%d) : Setting Country to %s", LOG_INF, byte);
		X509_NAME_add_entry_by_txt(nm, "C", MBSTRING_UTF8, byte, -1, -1, 0);
	} else if ( 0 == (strcasecmp(key,"S")) ) {
		log_trace("%s::%s(%d) : Setting State to %s", LOG_INF, byte);
		X509_NAME_add_entry_by_txt(nm, "S", MBSTRING_UTF8, byte, -1, -1, 0);
	} else if ( 0 == (strcasecmp(key,"L")) ) {
		log_trace("%s::%s(%d) : Setting locality to %s", LOG_INF, byte);
		X509_NAME_add_entry_by_txt(nm, "L", MBSTRING_UTF8, byte, -1, -1, 0);
	} else if ( 0 == (strcasecmp(key,"O")) ) {
		log_trace("%s::%s(%d) : Setting Organization to %s", LOG_INF, byte);
		X509_NAME_add_entry_by_txt(nm, "O", MBSTRING_UTF8, byte, -1, -1, 0);
	} else if ( 0 == (strcasecmp(key,"OU")) ) {
		log_trace("%s::%s(%d) : Setting Organizational Unit to %s", LOG_INF, byte);
		X509_NAME_add_entry_by_txt(nm, "OU", MBSTRING_UTF8, byte, -1, -1, 0);
	} else if ( 0 == (strcasecmp(key,"CN")) ) {
		log_trace("%s::%s(%d) : Setting Common Name to %s", LOG_INF, byte);
		X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_UTF8, byte, -1, -1, 0);
	} else {
		log_info("%s::%s(%d) : key = %s is unknown, skipping", LOG_INF, key);
	}
	return;
} /* populate_subject */

/**                                                                           */
/* Take an ASCII subject and convert it into an openSSL                       */
/* X509_NAME structure                                                        */
/*                                                                            */
/* @param  - [Input] : subject = ascii subject string                         */
/* @return - success = a ptr to a filled out X509_NAME subject                */
/*         - failure = NULL                                                   */
/*                                                                            */
static X509_NAME* parse_subject(const char* subject) /* parasoft-suppress METRICS-28_duplicated_1 "Complexity 21 is OK" */
{
	X509_NAME* subjName = NULL;
	char* keyBytes = NULL;
	char* strippedKey = NULL;
	unsigned long keyLen = 0;
	char* valBytes = NULL;
	char* strippedVal = NULL;
	unsigned long valLen = 0;
	char* localSubjectPtr = NULL;
	bool hasError = false;
	char* curPtr = NULL;
	int allocateMemorySize = 0;
	bool endOfSubject = false;

	subjName = X509_NAME_new();
	if(NULL == subjName) {
		log_error("%s::%s(%d) : Out of memory", LOG_INF);
		goto cleanup;
	}

	localSubjectPtr = strdup(subject);
    if (localSubjectPtr) {
        curPtr = localSubjectPtr;
        log_debug("%s::%s(%d) : Subject \"%s\" is %ld characters long", LOG_INF, curPtr, strlen(curPtr));

        log_trace("%s::%s(%d) : hasError = %s endOfSubject = %s", LOG_INF,
                  hasError ? "true" : "false",
                  endOfSubject ? "true" : "false");
    } else {
        log_error("%s::%s(%d) : Error allocating memory for subject", LOG_INF);
        hasError = true;
    }

	while(!hasError && !endOfSubject) {
		/* Get the Key */
		keyLen = strcspn(curPtr, "=");
		allocateMemorySize = (int)keyLen + 1;
		keyBytes = calloc(allocateMemorySize,sizeof(*keyBytes));
		if (NULL == keyBytes) {
			log_error("%s::%s(%d) : Out of memory", LOG_INF);
			goto cleanup;
		}		
		strncpy(keyBytes, curPtr, (int)keyLen);
		
		strippedKey = strip_blanks(keyBytes);
		log_verbose("%s::%s(%d) : Key: \"%s\" is %ld characters long", 
			LOG_INF, strippedKey, strlen(strippedKey));

		/* Now get the value for the key */
		curPtr += (keyLen+1); /* Advance past the equals character */
		if( *curPtr != '\0' ) {
			log_trace("%s::%s(%d) : localSubject is now \"%s\"", LOG_INF, curPtr);
			valLen = read_subject_value(curPtr, NULL);
			if(valLen != 0) {
				allocateMemorySize = (int)valLen + 1;
				valBytes = calloc(allocateMemorySize,sizeof(*valBytes));
				if (NULL == valBytes) {
					log_error("%s::%s(%d) : Out of memory", LOG_INF);
					goto cleanup;
				}			
				read_subject_value(curPtr, valBytes);
				curPtr += (valLen+1); // advance past the comma
				strippedVal = strip_blanks(valBytes);
			    log_verbose("%s::%s(%d) : Value: \"%s\" is %ld characters long", LOG_INF,
                            strippedVal, strlen(strippedVal));

				populate_subject(subjName, strippedKey, strippedVal);

				/* Don't try to advance if we just advanced past the */
				/* null-terminator */
				if( *(curPtr-1) != '\0' ) {
					if ( *curPtr != '\0' ) {
						/* Whitespace between RDNs should be ignored */
						log_trace("%s::%s(%d) : Stripping leading whitespace "
							"from \"%s\"", LOG_INF, curPtr);
						curPtr = strip_blanks(curPtr);
					} else {
						log_trace("%s::%s(%d) : Reached end of subject string", LOG_INF);
						endOfSubject = true;
					}
				} else {
					log_trace("%s::%s(%d) : Reached end of subject string", LOG_INF);
					endOfSubject = true;
				}
			} else {
				log_error("%s::%s(%d) : Input string '%s' is not a valid X500 name", LOG_INF, localSubjectPtr);
				hasError = true;
			}
		} else {
			log_error("%s::%s(%d) : Input string '%s' is not a valid X500 name", LOG_INF, localSubjectPtr);
			hasError = true;
		}
		if (keyBytes) free(keyBytes);
		if (valBytes) free(valBytes);
		/* Remember, *DONT* double free valBytes by freeing strippedVal */
		/* Likewise with strippedKey */
		keyBytes = NULL;
		valBytes = NULL;
		strippedVal = NULL;
		strippedKey = NULL;
		log_trace("%s::%s(%d) : hasError = %s endOfSubject = %s", LOG_INF, 
			hasError ? "true" : "false", endOfSubject ? "true" : "false");
	}

cleanup:
	if (localSubjectPtr) {
		log_trace("%s::%s(%d) : Freeing localSubjectPtr", LOG_INF);
		free(localSubjectPtr);
		localSubjectPtr = NULL;
	}
	if (keyBytes) free(keyBytes);
	if (valBytes) free(valBytes);
	/* Remember, *DONT* double free valBytes by freeing strippedVal */
	/* Likewise with strippedKey */
	keyBytes = NULL;
	valBytes = NULL;
	strippedVal = NULL;
	strippedKey = NULL;

	if (!hasError)
		return subjName;	
	else
		return NULL;
	
} /* parse_subject */

/**                                                                           */
/* Convert the base 64 encoded cert into a BIO structure to use in saving     */
/* NOTE: The Keyfactor platform sends down the certificate as a DER, except   */
/*       that DER is base 64 encoded to send via HTTP.  The result is a       */
/*       "naked PEM" that is, a PEM without the -----BEGIN CERTIFICATE-----   */
/*       and -----END CERTIFICATE---- in it.                                  */
/*                                                                            */
/* To get a true PEM to write to disk, we leverage the internal conversion    */
/* routines.  So, decode the "naked PEM" to creat a DER.  Then load the DER   */
/* into an openSSL internal data structure using a d2i_ function              */
/* then write the internal function as a PEM into a BIO structure.            */
/*                                                                            */
/* When the BIO gets populated, the ----BEGIN CERTIFICATE---- and -----END    */
/* CERTIFICATE----- are added.  In addition, this method verifies that the    */
/* data passed from the Keyfactor platform is a valid certificate structure   */
/* and wasn't corrupted in transit.                                           */
/*                                                                            */
/* @param  - [Output] : the bio to write the cert into                        */
/* @return - success : 0                                                      */
/*         - failure : error code                                             */
/*                                                                            */
static unsigned long write_cert_bio(BIO* bio, const char* b64cert)
{
	unsigned long errNum = 0;
	size_t outLen;
	X509* certStruct = NULL;
	bool result = false;
	char *certBytePtr = NULL;

    log_trace("%s::%s(%d) : Attempting to decode DER", LOG_INF);
	certBytePtr = base64_decode(b64cert, -1, &outLen);
    log_trace("%s::%s(%d) : Decoded certificate and got contents of \n%s", LOG_INF, certBytePtr);
	const unsigned char** tempPtrPtr = (const unsigned char**)&(certBytePtr);

	if (d2i_X509(&certStruct, tempPtrPtr, outLen)) {
		if (PEM_write_bio_X509(bio, certStruct))
            result = true;
	}

	if(result)
        log_verbose("%s::%s(%d) : Cert written to BIO", LOG_INF);
	else
		errNum = ERR_peek_last_error();

	if ( certStruct ) X509_free(certStruct);

	if (certBytePtr) {
		certBytePtr -= outLen;
		free(certBytePtr);
	}
	return errNum;
}

/**                                                                           */
/* Convert a private key into a PEM formatted BIO structure to use in saving  */
/*                                                                            */
/* @param  - [Output] : the bio to write the key into                         */
/* @param  - [Input] : A password (or NULL or "" if none) to encode the bio   */
/* @return - success : 0                                                      */
/*         - failure : error code                                             */
/*                                                                            */
static unsigned long write_key_bio(BIO* bio, const char* password, EVP_PKEY* key)
{
	unsigned long errNum = 0;

	/* If no password, then set it to null, else set it to password */
	const char* tmpPass = (password && strcmp(password, "") != 0) ? password : NULL;

	/* If we have a password, set the cypher to AES256 with CBC else null */
	const EVP_CIPHER* tmpCiph = (password && strcmp(password, "") != 0) ? EVP_aes_256_cbc() : NULL;

	if ( NULL == key ) {
		/* We want to save the global keyPair since no key was passed */
		if(PEM_write_bio_PKCS8PrivateKey(bio, keyPair, tmpCiph, NULL, 0, 0, (char*)tmpPass))
			log_verbose("%s::%s(%d) : Key written to BIO", LOG_INF);
		else
			errNum = ERR_peek_last_error();
	} else {
		/* Save the keypair passed to this function */
		if(PEM_write_bio_PKCS8PrivateKey(bio, key, tmpCiph, NULL, 0, 0, (char*)tmpPass))
			log_verbose("%s::%s(%d) : Key written to BIO", LOG_INF);
		else
			errNum = ERR_peek_last_error();
	}
	return errNum;
} /* write_key_bio */

/**                                                                           */
/* Retrieve ALL the certs from a PKCS7 structure.                             */
/*                                                                            */
/* NOTE: The PKCS7_get0_signers does NOT work.  I needed to reverse-engineer  */
/* openSSL to find out the way to get the certs from the pkcs7 bundle         */
/*                                                                            */
/* @param  - [Input]  : pkcs7 = the pkcs7 structure where the certs reside    */
/* @return - A pointer to a stack of x509 certificates                        */
/*           NULL = something went wrong                                      */
/*                                                                            */
static STACK_OF(X509)* get_pkcs7_certs(PKCS7* pkcs7) {

    STACK_OF(X509)* certs = NULL;

    if (NULL == pkcs7->d.ptr) {
        log_error("%s::%s(%d) : Error in pkcs7 data pointer", LOG_INF);
        PKCS7_free(pkcs7);
        return NULL;
    }

    if (NID_pkcs7_signed == OBJ_obj2nid(pkcs7->type)) {
        log_debug("%s::%s(%d) : PKCS#7 is tagged as signed", LOG_INF);
        if (NULL == pkcs7->d.sign->cert) {
            log_warn("%s::%s(%d) : No cert was attached to the signed cert data structure in openSSL", LOG_INF);
        } else {
            log_trace("%s::%s(%d) : Cert(s) were found in the signed data structure in openSSL", LOG_INF);
            certs = pkcs7->d.sign->cert;
        }
    } else if (NID_pkcs7_signedAndEnveloped == OBJ_obj2nid(pkcs7->type)) {
        log_debug("%s::%s(%d) : PKCS#7 is of a Signed and enveloped type", LOG_INF);
        if (NULL == pkcs7->d.signed_and_enveloped->cert) {
            log_warn("%s::%s(%d) : No cert was attached to the signed and enveloped "
            "cert data structure in openSSL", LOG_INF);
        } else {
            log_trace("%s::%s(%d) : Cert(s) were found in the signed and enveloped "
            "data structure in openSSL", LOG_INF);
            certs = pkcs7->d.signed_and_enveloped->cert;
        }
    }

    return certs;
} /* get_pkcs7_certs */

/**                                                                           */
/* Print an x509 name into a bio pre-pending with an optional title.          */
/*                                                                            */
/* @param  - [Output] : bio = the bio structure we want to populate           */
/* @param  - [Input]  : title = the title to pre-pend to the name             */
/* @param  - [Input]  : name = the X509_NAME we want to print                 */
/* @return - nothing                                                          */
/*                                                                            */
static void ssl_print_name_oneline(BIO* out, const char* title, const X509_NAME *name) {
    char* buf;

    if (NULL == out) {
        log_error("%s::%s(%d) : The BIO pointer is NULL, not allowed in this function call", LOG_INF);
        return;
    }

    if (NULL == title) {
        log_warn("%s::%s(%d) : The title is NULL, is this the desired call?", LOG_INF);
    } else {
        BIO_puts(out, title);
    }

    buf = X509_NAME_oneline(name, 0, 0);
    BIO_puts(out, buf);
    BIO_puts(out, "\n");

    if (buf) free(buf);
    return;
} /* ssl_print_name_oneline */

#ifdef __ALLOW_NAME_CHANGE__
/**                                                                           */
/* Add this to the CSR:                                                       */
/*    at-cmc-changeSubjectName ATTRIBUTE ::=                                  */
/*         { ChangeSubjectName IDENTIFIED BY id-cmc-changeSubjectName }       */
/*                                                                            */
/*      id-cmc-changeSubjectName OBJECT IDENTIFIER ::= {id-cmc 36}            */
/*                                                                            */
/*      ChangeSubjectName ::= SEQUENCE {                                      */
/*          subject             Name OPTIONAL,                                */
/*          subjectAlt          SubjectAltName OPTIONAL                       */
/*      }                                                                     */
/*      (WITH COMPONENTS {..., subject PRESENT} |                             */
/*            COMPONENTS {..., subjectAlt PRESENT} )                          */
/*                                                                            */
/*  @param : req is the CSR/PKCS10 request to modify                          */
/*  @param : curentSubject is the X509_NAME subject as defined by the cert    */
/*  @param : altSubject is the new subject & will be sent as a general name   */
/*  @return: true = successfully added this extension to the request          */
/*          false = something went wrong - review the output for more details */
/*                                                                            */
static bool change_subject_name(X509_REQ *req, X509_NAME* currentSubject, const char* altSubject) {
    ASN1_OBJECT* id_cmc_changeSubjectName = NULL;
    GENERAL_NAME* genName = NULL;
    bool result = false;

    /* Create the object identifier (OID) for id-cmc-changeSubjectName */
    id_cmc_changeSubjectName = OBJ_txt2obj(ID_CMC_CHANGESUBJECTNAME, 1); /* Only use the numerical name */
    if (!id_cmc_changeSubjectName) {
        log_error("%s::%s(%d) : Failed to create id-cmc-changeSubjectName OID", LOG_INF);
        return false;
    } else {
        log_verbose("%s::%s(%d) : Successfully created id-cmc-changeSubjectName OID as %s",
                    LOG_INF, ID_CMC_CHANGESUBJECTNAME);
    }

    /* Create the changeSubjectName extension attribute for the CSR */
    if ( NULL == (ext = X509_EXTENSION_new()) ) {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        goto exit;
    } else {
        log_trace("%s::%s(%d) : Successfully assigned memory with X509_EXTENSION_new", LOG_INF);
    }
    if ( !X509_EXTENSION_set_object(ext, id_cmc_changeSubjectName) ) {
        log_error("%s::%s(%d) : Out of memory assigning id_cmc_changeSubjectName to an extension object", LOG_INF);
        goto exit;
    } else {
        log_trace("%s::%s(%d) : Successfully set id_cmc_changeSubjectName to the extension object", LOG_INF);
    }

    /* Create the ASN1_SEQUENCE for this attribute */
    if ( NULL == (seq = sk_ASN1_TYPE_new_null()) ) {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        goto exit;
    } else {
        log_trace("%s::%s(%d) : Successfully created a new sequence object with sk_ASN1_TYPE_new_null()", LOG_INF);
    }

    /* Populate the subject portion of the sequence */
    /* We will set this first, as it appears that RFC 6402 section 2.8 requires the subject first */
    if ( !sk_ASN1_TYPE_push(seq, (ASN1_TYPE*)currentSubject) ) {
        log_error("%s::%s(%d) : Error populating the sequence with sk_ASN1_TYPE_push()", LOG_INF);
        goto exit;
    } else {
        log_trace("%s::%s(%d) : Successfully populated the sequence with the current subject", LOG_INF);
    }
    /* NOTE: Don't free this yet! It will be freed at the end of the function */

    if ( altSubject && (0 != strlen(altSubject)) ) {
        /* Populate the subjectAlt portion of the sequence as a general name */
        if ( NULL == (genName = GENERAL_NAME_new()) ) {
            log_error("%s::%s(%d) : Out of memory", LOG_INF);
            goto exit;
        } else {
            log_trace("%s::%s(%d) : Successfully allocated memory for a General Name object", LOG_INF);
        }
        genName->type = GEN_DNS;
        genName->d.dNSName = ASN1_IA5STRING_new();
        ASN1_STRING_set(genName->d.dNSName, altSubject, -1);
#if 0
        int r = sk_GENERAL_NAME_push(newSubject->entries, genName);
        if ( -1 == r || 0 == r ) {
            log_error("%s::%s(%d) : Error with sk_GENERAL_NAME_push in OpenSSL stack", LOG_INF);
            goto exit;
        } else {
            log_trace("%s::%s(%d) : successfully pushed General Name to newSubject", LOG_INF);
        }
#endif
        /* Add the subjectAlt sequence to the sequence */
        if ( !sk_ASN1_TYPE_push(seq, (ASN1_TYPE*)genName) ) {
            log_error("%s::%s(%d) : Error populating the sequence with sk_ASN1_TYPE_push()", LOG_INF);
            goto exit;
        } else {
            log_trace("%s::%s(%d) : Successfully populated the sequence with the SAN", LOG_INF);
        }
    }

    /* Add the data to the extension of the extension */
    if (SSL_SUCCESS != (X509_EXTENSION_set_data(ext, (ASN1_OCTET_STRING*)seq)) ) {
        log_error("%s::%s(%d) : Error setting the data for the X509 Extension", LOG_INF);
        goto exit;
    } else {
        log_trace("%s::%s(%d) : Successfully added the sequence to the data set", LOG_INF);
    }

    /* Add the extension to the CSR */
    if ( NULL == (extStack = sk_X509_EXTENSION_new_null()) ) {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        goto exit;
    }
    if ( !sk_X509_EXTENSION_push(extStack, ext) ) {
        log_error("%s::%s(%d) : Error pushing extension to stack object", LOG_INF);
        goto exit;
    }
    if ( 0 == (X509_REQ_add_extensions(req, extStack)) ) {
        log_error("%s::%s(%d) : Error performing X509_REQ_add_extensions function", LOG_INF);
        goto exit;
    } else {
        log_trace("%s::%s(%d) : Successfully added the changeSubjectName extension to the PKCS10/CSR", LOG_INF);
    }

    result = true;

exit:

    return result;
} /* change_subject_name */
#endif


/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/* Generate an RSA keypair & store it into tempKeypair                        */
/*                                                                            */
/* @param  - [Input] : keySize = the size of the RSA key                      */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
bool ssl_generate_rsa_keypair(int keySize) {
	char errBuf[120];
	BIGNUM* exp = NULL;
	unsigned long errNum = 0;
	int setWordResult = 0;
	bool bResult = false;

	log_trace("%s::%s(%d) : Assigning space for big number", LOG_INF);
	exp = BN_new();
	if (!exp) {
        log_error("%s::%s(%d) : out of memory when creating exponent "
        	"in genkey_rsa", LOG_INF);
        return NULL;
    }

    log_trace("%s::%s(%d) : Generating big number exp for RSA keygen", LOG_INF);
	setWordResult = BN_set_word(exp, RSA_DEFAULT_EXP);
	if ( 0 == setWordResult ) {
		log_error("%s::%s(%d) : Failed assigning exp for RSA keygen", LOG_INF);
		return NULL;
	}

	if (keyPair) {
		log_trace("%s::%s(%d) : Freeing newRsa & EVP keyPair", LOG_INF);
		EVP_PKEY_free(keyPair); /* Note this frees both structures */
		newRsa = NULL;
		keyPair = NULL;
	}

	log_trace("%s::%s(%d) : Creating new RSA space", LOG_INF);
	newRsa = RSA_new();
	if (!newRsa) {
        log_error("%s::%s(%d) : out of memory when creating RSA variable", LOG_INF);
        if ( exp ) BN_free(exp);
        return NULL;
    }

	log_trace("%s::%s(%d) : Generating the RSA key", LOG_INF);
	if(RSA_generate_key_ex(newRsa, keySize, exp, NULL))	{
		log_trace("%s::%s(%d) : RSA Key generated, converting to EVP structure", LOG_INF);
		if ( keyPair ) {
			log_warn("%s::%s(%d) : EVP keyPair wasn't freed possible memory leak", LOG_INF);
			keyPair = NULL;
		}
		
		keyPair = EVP_PKEY_new();
		if (!keyPair) {
			log_error("%s::%s(%d) : Out of memory allocating keypair", LOG_INF);
			goto exit;
		}

		log_trace("%s::%s(%d) : Assigning newRsa to keyPair", LOG_INF);
		EVP_PKEY_assign_RSA(keyPair, newRsa);
		bResult = true;
	} else {
		errNum = ERR_peek_last_error();
		ERR_error_string(errNum, errBuf);
		log_error("%s::%s(%d) : Unable to generate key pair: %s", LOG_INF, errBuf);
	}

exit:
	if ( exp )  {
		log_trace("%s::%s(%d) : Freeing big number", LOG_INF);
		BN_free(exp); 
	}
	/* NOTE: Do NOT free newRsa, it will corrupt EVP_PKEY */
	return bResult;
} /* generate_rsa_keypair */

/**                                                                           */
/* Generate an ECC keypair & store it into tempKeypair                        */
/*                                                                            */
/* @param  - [Input] : keySize = the size of the ECC key                      */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
bool ssl_generate_ecc_keypair(int keySize)
{
	char errBuf[120];
	int eccNid = -1;
	unsigned long errNum = 0;
	bool bResult = false;

	switch(keySize) {
		case 256:
			log_trace("%s::%s(%d) : Setting ECC curve to NID_X9_62_prime256v1", LOG_INF);
			eccNid = NID_X9_62_prime256v1;
			break;
		case 384:
			log_trace("%s::%s(%d) : Setting ECC curve to NID_secp384r1", LOG_INF);
			eccNid = NID_secp384r1;
			break;
		case 521:
			log_trace("%s::%s(%d) : Setting ECC curve to NID_secp521r1", LOG_INF);
			eccNid = NID_secp521r1;
			break;
		default:
			log_error("%s::%s(%d) : Invalid ECC key length: %d. Falling back to default curve", LOG_INF, keySize);
			eccNid = NID_X9_62_prime256v1;
			break;
		}

		if (keyPair) {
			log_trace("%s::%s(%d) : Freeing newEcc & EVP keyPair", LOG_INF);
			EVP_PKEY_free(keyPair); /* Note this frees both structures */
			newEcc = NULL;
			keyPair = NULL;
		}
		log_trace("%s::%s(%d) : Creating new ECC structure with named curve", LOG_INF);
		newEcc = EC_KEY_new_by_curve_name(eccNid);
		log_trace("%s::%s(%d) : set asn1 flag to Named Curve", LOG_INF);
		EC_KEY_set_asn1_flag(newEcc, OPENSSL_EC_NAMED_CURVE);
		log_trace("%s::%s(%d) : Generating new ECC key", LOG_INF);
		if(EC_KEY_generate_key(newEcc)) {

			if( keyPair ) {
				log_warn("%s::%s(%d) : keyPair was not freed, possible memory leak", LOG_INF);
				keyPair = NULL;
			}
			log_trace("%s::%s(%d) : Creating EVP keyPair structure", LOG_INF);
			keyPair = EVP_PKEY_new();
			
			log_trace("%s::%s(%d) : New keypair created, assigning to EVP keyPair", LOG_INF);
			if(0 == EVP_PKEY_assign_EC_KEY(keyPair, newEcc)) {
				log_error("%s::%s(%d) : Error assigning keyPair", LOG_INF);
				return NULL;
			} else {
				log_trace("%s::%s(%d) : Successfully assigned ECC keypair", LOG_INF);
				bResult = true;
			}
		} else {
			errNum = ERR_peek_last_error();
			ERR_error_string(errNum, errBuf);
			log_error("%s::%s(%d) : Unable to generate key pair: %s", LOG_INF, errBuf);
		}
		
	return bResult;
} /* generate_ecc_keypair */

/**                                                                           */
/* Create a CSR using the subject provided and the temporary key keyPair.     */
/* Return an ASCII CSR (minus the header and footer).                         */
/*                                                                            */
/* @param  - [Input]  : asciiSubject string with the subject line             */
/*                      e.g., CN=1234,OU=NA,O=Keyfactor,C=US                  */
/* @param  - [Output] : csrLen the # of ASCII characters in the csr           */
/* @param  - [Output]: pMessage = a string array containing any messages      */
/*                     we want to pass back to the calling function           */
/* @return - success : the CSR string minus the header and footer             */
/*           failure : NULL                                                   */
/*                                                                            */
#ifdef __ALLOW_NAME_CHANGE__
char* ssl_generate_csr(const char* asciiSubject, size_t* csrLen, const bool useChallengePassword, const char* pw,
                       const char* asciiAltSubject, const bool useNameChange)
#else
char* ssl_generate_csr(const char* asciiSubject, size_t* csrLen, const bool useChallengePassword, const char* pw)
#endif
{
	X509_REQ* req = NULL;
	X509_NAME* subject = NULL;
    ASN1_PRINTABLESTRING* challengePassword = NULL;
	unsigned char reqBytes[MAX_CSR_SIZE] = {0};
	char* csrString = NULL;
	int result = SSL_SUCCESS;
	char errBuf[120];
	int errNum = 0;

#if 0
    log_debug("%s::%s(%d) : asciiSubject = %s", LOG_INF, asciiSubject);
    log_debug("%s::%s(%d) : useChallengePassword = %s", LOG_INF, useChallengePassword ? "true" : "false");
    log_debug("%s::%s(%d) : pw = %s", LOG_INF, pw ? pw : "null");
#endif
	
	/*************************************************************************/
	/* 1.) Set up the CSR as a new x509 request by creating a blank request  */
	/*     then adding in the public key, setting the subject, and signing   */
	/*     it with the private key.                                          */
	/*************************************************************************/
	log_verbose("%s::%s(%d) : Setting up a CSR", LOG_INF);
	req = X509_REQ_new();	/* Ask for the new structure */
	if ( NULL == req ) {
		log_error("%s::%s(%d) : Out of memory", LOG_INF);
		return NULL;
	} else {
        log_trace("%s::%s(%d) : Memory allocated for a new CSR", LOG_INF);
    }

	result = X509_REQ_set_version(req, X509_VERSION_3);
	if ( SSL_SUCCESS != result ) {
		log_error("%s::%s(%d) : Failed to set REQ version", LOG_INF);
		goto exit;
	} else {
        log_trace("%s::%s(%d) : Successfully set the request to version %d", LOG_INF, X509_VERSION_3);
    }

    if (useChallengePassword) {
        if ( (pw) && (0 < strlen(pw)) ) {
            challengePassword = ASN1_PRINTABLESTRING_new();
            if (!challengePassword) {
                log_error("%s::%s(%d) : Error out of memory", LOG_INF);
                goto exit;
            }

            if ( !ASN1_STRING_set(challengePassword, pw, strlen(pw)) ) {
                log_error("%s::%s(%d) : Failed while setting challenge password", LOG_INF);
                goto exit;
            }

            if (!X509_REQ_add1_attr_by_NID(req, NID_pkcs9_challengePassword, V_ASN1_PRINTABLESTRING,
                                           challengePassword->data, challengePassword->length)) {
                log_error("%s::%s(%d) : Failed while trying to add challenge password to csr", LOG_INF);
                goto exit;
            }
            else {
                log_trace("%s::%s(%d) : Successfully added ASN1 challenge password to X509 request", LOG_INF);
            }
        } else {
            log_error("%s::%s(%d) : Error must have a challenge password set when using it", LOG_INF);
            goto exit;
        }
    } else {
        log_trace("%s::%s(%d) : Not using challenge password, skipping adding to CSR", LOG_INF);
    }

	log_trace("%s::%s(%d) : Converting subject %s into openSSL structure", LOG_INF, asciiSubject);
	subject = parse_subject(asciiSubject);

	/* Add the X509_NAME to the req */
	result = X509_REQ_set_subject_name(req, subject);
    if ( SSL_SUCCESS != result ) {
        errNum = ERR_peek_last_error();
        ERR_error_string(errNum, errBuf);
        log_error("%s::%s(%d) : CSR subject name set failed with code, 0x%X = %s", LOG_INF, result, errBuf);
        csrString = NULL;
        goto exit;
    }

#ifdef __ALLOW_NAME_CHANGE__
    if ( useNameChange ) {
        if ( change_subject_name(req, subject, asciiAltSubject) ) {
            log_trace("%s::%s(%d) : Successfully set the changeSubjectName attribute", LOG_INF);
        } else {
            log_error("%s::%s(%d) : Error setting the changeSubjectName attribute", LOG_INF);
            csrString = NULL;
            goto exit;
        }
    } else {
        log_trace("%s::%s(%d) : No name changeSubjectName requested, skipping adding extension", LOG_INF);
    }
#endif

    log_trace("%s::%s(%d) : Adding the public key to the CSR", LOG_INF);
    result = X509_REQ_set_pubkey(req, keyPair); // Add the public key
    if ( SSL_SUCCESS == result ) {
        /* Ask for the private key to sign the CSR request */
        result = X509_REQ_sign(req, keyPair, EVP_sha256());
        /* wolfSSL returns WOLF_SSL_SUCCESS (defined as 1)  */
        /* or WOLF_SSL_FAILURE (defined as 0) */
        /* opoenSSL returns the size of the signature or 0 if it fails */
        if ( 0 == result ) {
            errNum = ERR_peek_last_error();
            ERR_error_string(errNum, errBuf);
            log_error("%s::%s(%d) : CSR signing failed with code, 0x%X = %s", LOG_INF, result, errBuf);
            csrString = NULL;
        } else {
            log_trace("%s::%s(%d) : Successfully signed CSR", LOG_INF);
            result = SSL_SUCCESS;
        }
    } else {
        errNum = ERR_peek_last_error();
        ERR_error_string(errNum, errBuf);
        log_error("%s::%s(%d) : CSR set of public key failed with code, 0x%X = %s", LOG_INF, result, errBuf);
        csrString = NULL;
    }


	/*************************************************************************/
	/* 2.) Take the resulting DER, encode it and convert it to a             */
	/*     string; the result is a PEM without the BEGIN CERTIFICATE REQUEST */
	/*     and END CERTIFICATE REQUEST                                       */
	/*************************************************************************/
	if( SSL_SUCCESS == result )	{
		log_verbose("%s::%s(%d) : Encoding the CSR and converting it to a base 64 encoded string.", LOG_INF);
        unsigned char* tempReqBytes = reqBytes;
        /* Encode the CSR request as a PKCS#10 certificate request */
        int writeLen = i2d_X509_REQ(req, &tempReqBytes);
        /* Now convert this structure to an ASCII string */
        csrString = base64_encode(reqBytes, (size_t)writeLen, false, NULL);
        *csrLen = (size_t)writeLen; // GM Specific Code
        log_trace("%s::%s(%d) : csrString=%s", LOG_INF, csrString);
        log_trace("%s::%s(%d) : csrLen = %ld", LOG_INF, *csrLen);
        if (MAX_CSR_SIZE < *csrLen) {
            log_error("%s::%s(%d) : The length of the CSR = %ld which is longer than the maximum defined "
                      "length of %d -- ABORTING, please increase the maximum CSR length above %ld and re-compile",
                      LOG_INF, *csrLen, MAX_CSR_SIZE, *csrLen);
            exit(EXIT_FAILURE);
        }
	}

exit:
	if ( req ) {
        log_trace("%s::%s(%d) : Freeing req via X509_REQ_free", LOG_INF);
        X509_REQ_free(req);
        req = NULL;
    }
    if ( seq ) {
        log_trace("%s::%s(%d) : Freeing the sequence", LOG_INF);
        sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
        subject = NULL;
    }
	if ( subject ) {
        log_trace("%s::%s(%d) : Freeing subject via X509_NAME_free", LOG_INF);
        X509_NAME_free(subject);
        subject = NULL;
    }
    if ( extStack ) {
        log_trace("%s::%s(%d) : Freeing extension stack", LOG_INF);
        sk_X509_EXTENSION_pop_free(extStack, X509_EXTENSION_free);
        ext = NULL;
        extStack = NULL;
    }
    if ( ext ) {
        log_trace("%s::%s(%d) : Freeing extension data", LOG_INF);
        X509_EXTENSION_free(ext);
        ext = NULL;
    }

	return csrString;
} /* ssl_generate_csr */

/**                                                                           */
/* Save the cert and key to the locations requested                           */
/* Store the locally global variable keyPair to the location requested        */
/*                                                                            */
/* @param  - [Input] : storePath = the store location for the cert            */
/* @param  - [Input] : keyPath = the location to save the key, if NULL or     */
/*                     blank, store the encoded key appended to the cert.     */
/* @param  - [Input] : password = the password for the private key            */
/* @param  - [Input] : cert = The cert in an ASCII encoded string             */

/* @return - unsigned long error code                                         */
/*                                                                            */
unsigned long ssl_save_cert_key(const char* storePath, const char* keyPath,	const char* password, const char* cert) {

	BIO* certBIO = NULL;
	BIO* keyBIO = NULL;
	unsigned long err = 0;
	char errBuf[120];

#if 0
    log_debug("%s::%s(%d) : storePath = %s", LOG_INF, storePath ? storePath : "null");
    log_debug("%s::%s(%d) : keyPath = %s", LOG_INF, keyPath ? keyPath : "null");
    log_debug("%s::%s(%d) : password = %s", LOG_INF, password ? password : "null");
    log_debug("%s::%s(%d) : cert = \n%s", LOG_INF, cert ? cert : "null");
#endif

    if (storePath) {
        if ( NULL == cert ) {
            log_error("%s::%s(%d) : Error, storePath defined but no certificate passed to this function", LOG_INF);
            return -1;
        }
        log_trace("%s::%s(%d) : Saving certificate to store at %s", LOG_INF, storePath);
        err = backup_file(storePath);
        if (err != 0 && err != ENOENT) {
            char *errStr = strerror(err);
            log_error("%s::%s(%d) : Unable to backup store at %s: %s\n", LOG_INF, storePath, errStr);
        } else {
            /* Write the cert as a full PEM into memory */
            certBIO = BIO_new(BIO_s_mem());
            keyBIO = NULL;

            err = write_cert_bio(certBIO, cert);
            if (err) {
                ERR_error_string(err, errBuf);
                log_error("%s::%s(%d) : Unable to write certificate to BIO: %s", LOG_INF, errBuf);
            }
        }

        if (!err) {
            char *data = NULL;
            long len = BIO_get_mem_data(certBIO, &data);
            err = replace_file(storePath, data, len, true);

            if (err) {
                char *errStr = strerror(err);
                log_error("%s::%s(%d) : Unable to write store at %s: %s", LOG_INF, storePath, errStr);
            }
        }

    } else {
        log_debug("%s::%s(%d) : No certificate store passed to ssl_save_cert_key, skipping certificate save", LOG_INF);
    }

    if (keyPath) {
        if (!err) {
            keyBIO = BIO_new(BIO_s_mem());
            err = write_key_bio(keyBIO, password, NULL);

            if (err) {
                ERR_error_string(err, errBuf);
                log_error("%s::%s(%d) : Unable to write key to BIO: %s", LOG_INF, errBuf);
            }
        }
        if (!err) {
            char *data = NULL;
            long len = BIO_get_mem_data(keyBIO, &data);
            err = replace_file(keyPath, data, len, true);

            if (err) {
                char *errStr = strerror(err);
                log_error("%s::%s(%d) : Unable to write store at %s: %s", LOG_INF, keyPath, errStr);
            }
        }
    } else {
        log_debug("%s::%s(%d) : No keyPath defined, so skipping saving the key", LOG_INF);
    }

	if ( certBIO ) BIO_free(certBIO);
	if ( keyBIO  ) BIO_free(keyBIO);
	return err;
} /* ssl_save_cert_key */

/**                                                                           */
/*  Take a PKCS7 DER binary & convert it into an x.509 PEM file               */
/*                                                                            */
/*  @param pkcs7Der = the binary data stream                                  */
/*  @param len = the length of the binary data stream                         */
/*  @param addSubjects = yes to add text subjects, no to only output the PEM  */
/*  @returns NULL = something went wrong                                      */
/*           success = an x.509 PEM with all of the certs in the PKCS7 DER    */
/*                                                                            */
/* NOTE: This function allocates new memory and returns it,                   */
/*       the calling program must free the memory                             */
/*                                                                            */
char* ssl_convert_P7_to_pem(const unsigned char* pkcs7Der, const size_t len, bool addSubjects) {
    char* pem = NULL;
    long cert_len = 0;
    char* bio_pointer = NULL;
    X509* x509_cert = NULL;
    STACK_OF(X509)* certs = NULL;
    int num_certs = 0;

    if (NULL == pkcs7Der) {
        log_error("%s::%s(%d) : Invalid NULL pointer passed as pkcs7_der", LOG_INF);
        return NULL;
    }

    /* Read the DER bytes into an openSSL PKCS7 data structure */
    PKCS7* pkcs7 = d2i_PKCS7(NULL, &pkcs7Der, len);
    if (!pkcs7) {
        log_error("%s::%s(%d) : Failed to parse PKCS#7 DER", LOG_INF);
        return NULL;
    }
    log_trace("%s::%s(%d) : Successfully read the DER into a PKCS7 structure", LOG_INF);

    /* Get a pointer to the certs in the pkcs7 data structure */
    if ( NULL == (certs = get_pkcs7_certs(pkcs7)) ) {
        log_error("%s::%s(%d) : No certificate found in PKCS#7 data structure -- structure is NULL", LOG_INF);
        PKCS7_free(pkcs7);
        return NULL;
    }

    if (1 > sk_X509_num(certs)) {
        log_error("%s::%s(%d) : No certificate found in PKCS#7 -- cert count is 0", LOG_INF);
        PKCS7_free(pkcs7);
        return NULL;
    }
    num_certs = sk_X509_num(certs);
    log_trace("%s::%s(%d) : Successfully read %d certificates in the bundle", LOG_INF, num_certs);

    /* Create a BIO data structure to put the openSSL data into */
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        log_error("%s::%s(%d) : Out of memory or other openSSL bio creation failure", LOG_INF);
        PKCS7_free(pkcs7);
        return NULL;
    }
    log_trace("%s::%s(%d) : Successfully allocated and initialized a BIO buffer for the certs", LOG_INF);

    /* Extract each certificate (one at a time), convert it to a PEM, and add it to the result */
    for (int i = 0; num_certs > i; i++) {
        x509_cert = sk_X509_value(certs, i);
        if (!x509_cert) {
            log_warn("%s::%s(%d) : Warning failed to extract x509 cert number %d", LOG_INF, i);
            continue;
        }

        if (addSubjects) {
            /* Write some cert data as a comment in the PEM file */
            ssl_print_name_oneline(bio, "# subject=", X509_get_subject_name(x509_cert));
            ssl_print_name_oneline(bio, "# issuer=", X509_get_issuer_name(x509_cert));
        }

        /* Write the cert as an X509 PEM to the BIO data structure */
        if (!PEM_write_bio_X509(bio, x509_cert)) {
            log_warn("%s::%s(%d) : Warning failed to write certificate number %d to bio", LOG_INF, i);
            continue;
        }
    }

    /* Get a pointer to the data portion of the BIO, this is where the PEM is stored */
    cert_len = BIO_get_mem_data(bio, &bio_pointer);
    if (0 >= cert_len) {
        log_error("%s::%s(%d) : Failed to find pointer to PEM data &/or PEM data length in BIO", LOG_INF);
        goto exit;
    }

    /* Create the PEM string & copy the certs into it, remembering to append a NULL to the end of the string */
    pem = calloc(cert_len + 1, sizeof(*pem));
    if (pem) {
        memcpy(pem, bio_pointer, cert_len);
        pem[cert_len] = '\0';
    } else {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
    }

exit:
    PKCS7_free(pkcs7);
    BIO_free_all(bio);
    return pem; /* remember to free this in your calling program */
} /* ssl_convert_P7_to_pem */

/**                                                                           */
/*  Take an x.509 PEM certificate from the file system and get the cert's DN  */
/*                                                                            */
/*  @param fileLocation = path and filename of the x.509 PEM certificate      */
/*  @param maxSubjectLen = the maximum size the DN can be                     */
/*                                                                            */
/* NOTE: This function allocates new memory and returns it,                   */
/*       the calling program must free the memory                             */
/*                                                                            */
char* ssl_get_subject(const char* fileLocation, const unsigned int maxSubjectLen) {
    char tempSubject[maxSubjectLen+1];
    char* subject = NULL;
    X509* certificate = NULL;
    X509_NAME* x509Subject = NULL;
    BIO* bio = NULL;
    FILE* fp = NULL;

    if ( NULL == (fp = fopen(fileLocation, "r")) ) {
        log_error("%s::%s(%d) : Error reading certificate at location %s -"
                  " make sure you have read permissions and the file exists", LOG_INF, fileLocation);
        return NULL;
    }

    if ( NULL == (certificate = PEM_read_X509(fp, NULL, NULL, NULL)) ) {
        log_error("%s::%s(%d) : Error reading PEM file at location %s -"
                  " is the file an actual x509 PEM?", LOG_INF, fileLocation);
        fclose(fp);
        return NULL;
    }
    fclose(fp); /* Done with this */

    x509Subject = X509_get_subject_name(certificate);
    if ( NULL == (bio = BIO_new(BIO_s_mem())) ) {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        goto exit;
    }

    if ( 0 >= X509_NAME_print_ex(bio, x509Subject, 0, XN_FLAG_RFC2253) ) {
        log_error("%s::%s(%d) : Error extracting name from BIO", LOG_INF);
        unsigned long longErr = ERR_peek_error();
        char errMsgBuf[256];
        ERR_error_string_n(longErr, errMsgBuf, (size_t)256);
        log_error("%s::%s(%d) : Error message is %s", LOG_INF, errMsgBuf);
        goto exit;
    }

    /* NOTE: BIO_gets is always a NULL-terminated string, per https://www.openssl.org/docs/man3.1/man3/BIO_gets.html */
    if ( -1 == BIO_gets(bio, tempSubject, sizeof(tempSubject)) ) {
        log_error("%s::%s(%d) : Error writing name to temporary buffer", LOG_INF);
        goto exit;
    }

    if ( NULL == (subject = calloc(strlen(tempSubject)+1, sizeof(*subject))) ) {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        goto exit;
    }
    memcpy(subject, tempSubject, strlen(tempSubject) + 1 );

exit:
    if (certificate) X509_free(certificate);
    if (bio) BIO_free(bio);
    return subject;
} /* ssl_get_subject */

/**                                                                           */
/* Clean up all of the openSSL items that are outstanding                     */
/*                                                                            */
/* @param  - none                                                             */
/* @return - none                                                             */
/*                                                                            */
void ssl_cleanup(void)
{
	log_trace("%s::%s(%d) : Cleaning up openssl", LOG_INF);
	if (keyPair) EVP_PKEY_free(keyPair);
	/* NOTE: The RSA and ECC key are freed by this call */
#ifndef OPENSSL_IS_BORINGSSL
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
#endif
    return;
} /* ssl_cleanup */

/**                                                                           */
/* Initialize the platform to use openssl                                     */
/*                                                                            */
/* @param  - none                                                             */
/* @return - none                                                             */
/*                                                                            */
void ssl_init(void)
{
#ifndef OPENSSL_IS_BORINGSSL
	log_trace("%s::%s(%d) : Adding openSSL algorithms", LOG_INF);
	OpenSSL_add_all_algorithms();
	log_trace("%s::%s(%d) : Loading Crypto error strings", LOG_INF);
	ERR_load_crypto_strings();
#endif
    log_info("%s::%s(%d) : Currently using OpenSSL version: %s\n", LOG_INF, OpenSSL_version(OPENSSL_VERSION));
	return;
} /* ssl_init */


/* suppress the deprecated error message for now */ //:TODO Update for OpenSSL 3.0
#pragma GCC diagnostic pop

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/
