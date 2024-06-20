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

#include "../include/main.h"
#include "../include/logging.h"
#include "../include/httpclient.h"
#include "../lib/include/base64.h"
#include "../include/file_utilities.h"
#include "../include/csr.h"
#include "../include/options.h"
#include "../include/ssl_interface.h"
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <openssl/engine.h>


/******************************************************************************/
/***************************** GLOBAL VARIABLES *******************************/
/******************************************************************************/
uint16_t ECC_KEY_SIZES[] = {256, 384, 521};
uint16_t RSA_KEY_SIZES[] = {1024, 1536, 2048, 3072, 4096, 6144, 8192};

/******************************************************************************/
/***************************** LOCAL DEFINES  *********************************/
/******************************************************************************/
#define DEFAULT_EJBCA_EST_ALIAS           "est"
#define DEFAULT_BIRTH_CERT_FILE           NULL
#define DEFAULT_CACERT_FILE               "certs/cacerts.pem"
#define DEFAULT_BIRTH_KEY_FILE            NULL
#define DEFAULT_BIRTH_KEY_PASSWORD        NULL
#define DEFAULT_CLIENT_CERT_FILE          "certs/client-cert.pem"
#define DEFAULT_CLIENT_KEY_FILE           "certs/client-key.pem"
#define DEFAULT_CLIENT_KEY_PASSWORD       NULL
#define DEFAULT_KEY_TYPE                  "RSA"
#define DEFAULT_PASSWORD                  NULL
#define DEFAULT_TRUST_STORE               "certs/trust.store"
#define DEFAULT_USERNAME                  NULL
#define DEFAULT_BASE_EJBCA_URL            "https://ejbca-node-01"
#define DEFAULT_EST_EE_USERNAME           "unique_device"
#define DEFAULT_EST_EE_ENROLLMENTCODE_KEY "L"
#define DEFAULT_EST_EE_ENROLLMENTCODE     "unique_device_enrollment_code"
#define DEFAULT_CHALLENGE_PASSWORD        NULL
#define DEFAULT_ALT_SUBJECT_NAME          NULL

static const char* ejbca_test_endpoint_url = "/ejbca/publicweb/healthcheck/ejbcahealth";
static const char* ejbca_well_known = "/.well-known/est/";
static const char* ejbca_est_cacerts_url = "/cacerts";
static const char* ejbca_est_simpleenroll_url = "/simpleenroll";
static const char* ejbca_est_simplereenroll_url = "/simplereenroll";

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/
int http_retries = 1;
int http_retry_delay = 1;
char* csr = NULL;
size_t csr_len = 0;

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/*************** THAT CAN BE MODIFIED VIA COMMAND LINE ARGUMENTS **************/
/******************************************************************************/
char* ejbca_est_alias;                              /* --alias for specifying the alias for EJBCA */
char* birth_cert_file;                              /* --birthcert file location of birth certificate */
char* cacert_file;                                  /* --cacert for storing the Aliases cacerts.pem */
char* birth_key_file;                               /* --birthkey file location of birth key */
char* birth_key_password;                           /* --birthkeypass is the birth key password */
char* challenge_password;                           /* --challengepass to specify the use of a challenge password */
char* client_cert_file;                             /* --clientcert where to store the device's cert */
char* client_key_file;                              /* --clientkey where to store the device's client key*/
char* client_key_password;                          /* --clientkeypass to provide an (optional) password */
char* key_type;                                     /* --keytype for specifying the keytype */
                                                    /* --loglevel is logging level */
bool new_device = false;                            /* --newdevice ignore existing certs, note EE must be New */
bool skip_ejbca_check = false;                      /* --skiphealth skip ejbca health check */
char* password = NULL;                              /* --password for Basic Auth */
bool reenroll_only = false;                         /* --reenroll to only perform the reenrollment portion */
char* subject;                                      /* --subject for changing the subject */
bool  subject_supplied_on_command_line = false;     /* This is false unless --subject is used */
char* trust_store;                                  /* --trust for trusting the EJBCA Management CA/RA endpoint */
char* username = NULL;                              /* --username for Basic Auth */
char* base_ejbca_url;                               /* --url for specifying the base URL for ejbca */
char* est_ee_username;                              /* --eeuser to specify the end entities username */
char* est_ee_enrollmentcode_key;                    /* --eekey to specify the DN code for the enrollment code */
char* est_ee_enrollmentcode;                        /* --eepass to specify the end entities enrollment code */
#ifdef __ALLOW_NAME_CHANGE__
char* alt_subject_name;                             /* --altsubject to specify a SAN if we are allowing name change */
bool  allow_name_change = false;                    /* --allownamechange to specify DN change from certificate */
#endif
uint16_t key_size = 4096;                           /* --keysize for specifying the keysize */
bool print_usage_only = false;                      /* --help to print usage only */
bool est_vendormode = false;                        /* If a birthcert is present, this becomes true */
bool  use_challenge_password = false;               /* If a challenge password is set, this becomes true */
bool use_basic_authentication = false;              /* If a username or password is set, this becomes true */

/******************************************************************************/
/************************ LOCAL FUNCTION PROTOTYPES ***************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/* Set a single default value                                                 */
/*                                                                            */
/* @return - true = successfully set the default                              */
/*          false = Out of memory error was thrown                            */
/*                                                                            */
static bool set_a_default(char* default_constant, char** target) {
    bool result = true;
    if (default_constant) {
        *target = strdup(default_constant);
        if (NULL == (*target)) {
            fprintf(stderr, "%s::%s(%d) : Out of memory\n", LOG_INF);
            result = false;
        }
    } else {
        *target = NULL;
    }
    return result;
} /* set_a_default */

/**                                                                           */
/* Set standard default values                                                */
/*                                                                            */
/* @return - true = successfully set all defaults                             */
/*          false = Out of memory error was thrown                            */
/*                                                                            */
static bool set_standard_defaults(void) {
    if (!set_a_default(DEFAULT_CACERT_FILE, &cacert_file)) return false;
    if (!set_a_default(DEFAULT_TRUST_STORE, &trust_store)) return false;
    if (!set_a_default(DEFAULT_KEY_TYPE, &key_type)) return false;
    return true;
} /* set_standard_defaults */

/**                                                                           */
/* Set default values for the EJBCA instance we are connecting to             */
/*                                                                            */
/* @return - true = successfully set all defaults                             */
/*          false = Out of memory error was thrown                            */
/*                                                                            */
static bool set_ejbca_defaults(void) {
    if (!set_a_default(DEFAULT_EJBCA_EST_ALIAS, &ejbca_est_alias)) return false;
    if (!set_a_default(DEFAULT_BASE_EJBCA_URL, &base_ejbca_url)) return false;
    return true;
} /* set_ejbca_defaults */

/**                                                                           */
/* Set default values for the client certificate things                       */
/*                                                                            */
/* @return - true = successfully set all defaults                             */
/*          false = Out of memory error was thrown                            */
/*                                                                            */
static bool set_client_cert_defaults(void) {
    if (!set_a_default(DEFAULT_CLIENT_CERT_FILE, &client_cert_file)) return false;
    if (!set_a_default(DEFAULT_CLIENT_KEY_FILE, &client_key_file)) return false;
    if (!set_a_default(DEFAULT_CLIENT_KEY_PASSWORD, &client_key_password)) return false;
    return true;
} /* set_client_cert_defaults */

/**                                                                           */
/* Set default values if we are using a birthing certificate                  */
/*                                                                            */
/* @return - true = successfully set all defaults                             */
/*          false = Out of memory error was thrown                            */
/*                                                                            */
static bool set_birthing_cert_defaults(void) {
    if (!set_a_default(DEFAULT_BIRTH_CERT_FILE, &birth_cert_file)) return false; /* parasoft-suppress BD-PB-CC "Required to test for presence of #defines" */
    if (!set_a_default(DEFAULT_BIRTH_KEY_FILE, &birth_key_file)) return false; /* parasoft-suppress BD-PB-CC "Required to test for presence of #defines" */
    if (!set_a_default(DEFAULT_BIRTH_KEY_PASSWORD, &birth_key_password)) return false; /* parasoft-suppress BD-PB-CC "Required to test for presence of #defines" */
    return true;
} /* set_birthing_cert_defaults */

/**                                                                           */
/* Set default values for the end entity information                          */
/*                                                                            */
/* @return - true = successfully set all defaults                             */
/*          false = Out of memory error was thrown                            */
/*                                                                            */
static bool set_end_entity_defaults(void) {
    if (!set_a_default(DEFAULT_EST_EE_USERNAME, &est_ee_username)) return false;
    if (!set_a_default(DEFAULT_EST_EE_ENROLLMENTCODE_KEY, &est_ee_enrollmentcode_key)) return false;
    if (!set_a_default(DEFAULT_EST_EE_ENROLLMENTCODE, &est_ee_enrollmentcode)) return false;
    return true;
} /* set_end_entity_defaults */

/**                                                                           */
/* Set default values if we are using username/password for authentication    */
/*                                                                            */
/* @return - true = successfully set all defaults                             */
/*          false = Out of memory error was thrown                            */
/*                                                                            */
static bool set_username_password_defaults(void) {
    if (!set_a_default(DEFAULT_PASSWORD, &password)) return false; /* parasoft-suppress BD-PB-CC "Required to test for presence of #defines" */
    if (!set_a_default(DEFAULT_USERNAME, &username)) return false; /* parasoft-suppress BD-PB-CC "Required to test for presence of #defines" */
    if (!set_a_default(DEFAULT_CHALLENGE_PASSWORD, &challenge_password)) return false; /* parasoft-suppress BD-PB-CC "Required to test for presence of #defines" */
    return true;
} /* set_username_password_defaults */

/**                                                                           */
/* Set default values                                                         */
/*                                                                            */
/* @return - true = successfully set all defaults                             */
/*          false = Out of memory error was thrown                            */
/*                                                                            */
static bool set_defaults() {
    if (!set_standard_defaults()) return false;
    if (!set_ejbca_defaults()) return false;
    if (!set_client_cert_defaults()) return false;
    if (!set_birthing_cert_defaults()) return false;
    if (!set_end_entity_defaults()) return false;
    if (!set_username_password_defaults()) return false;
    return true;
} /* set_defaults */

/**                                                                           */
/* Concatenate two strings into a third string                                */
/*                                                                            */
/* NOTE: You must free the function's returned result in your program         */
/*                                                                            */
/* @param  - firstPart = the first part of the string                         */
/* @param  - secondPart = the string pasted after the first part              */
/* @return - A concatenated string you need to free OR                        */
/*          NULL for failure                                                  */
/*                                                                            */
static char* string_cat(const char* firstPart, const char* secondPart) {
    if (!firstPart || !secondPart) {
        log_error("%s::%s(%d) : Error one or more passed parameters is NULL", LOG_INF);
        return NULL;
    }
    size_t firstPartLen = strlen(firstPart);
    size_t secondPartLen = strlen(secondPart);
    char* result = calloc(firstPartLen + secondPartLen + 1, sizeof(*result));
    if (!result) {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        return NULL;
    }
    (void)memcpy(result, firstPart, firstPartLen);
    (void)memcpy(result+firstPartLen, secondPart, secondPartLen);
    result[secondPartLen + firstPartLen] = '\0';
    return result;
} /* string_cat */

/**                                                                           */
/*	Try to connect to our EJBCA instance; requires REST to be enabled.        */
/*                                                                            */
/*	@param  - [Input] url = The base url to hit                               */
/*	@return - success : true                                                  */
/*			  failure : false                                                 */
/*                                                                            */
static bool test_ejbca_connection(const char* url) {
    const char* headersToSend[1] = {"Accept: text/plain"};
    char* response = NULL;
    bool result = false;

    int r =
        http_get_json(url,
                      username, password,
                      trust_store,
                      client_cert_file, client_key_file, client_key_password,
                      headersToSend, 1,
                      &response,
                      http_retries, http_retry_delay);
    if (HTTP_CLIENT_SUCCESS != r) {
        log_error("%s::%s(%d) : Bad data received from EST endpoint", LOG_INF);
        if (response) free(response);
        return false;
    }

    if (0 == strcasecmp("ALLOK", response)) {
        log_info("%s::%s(%d) : EJBCA reports status = %s", LOG_INF, response);
        result = true;
    } else {
        log_error("%s::%s(%d) : EJBCA reports status = %s", LOG_INF, response);
        result = false;
    }

    if (response) free(response);
    return result;
} /* test_ejbca_connection */

/**                                                                           */
/*	Get the CA Certs in base64 encoding.  Decode the certs into PKCS#7 format */
/*  Convert the DER PKCS#7 format into a PEM.                                 */
/*                                                                            */
/*	@param  - [Input] url = The base url to hit                               */
/*	@return - success : true                                                  */
/*			  failure : false                                                 */
/*                                                                            */
static bool get_ca_certs(const char* url) {
    size_t derLen = 0;
    bool result = false;
    unsigned char* pkcs7Der = NULL;
    char* pem = NULL;
    const char* headersToSend[1] = { "Accept: application/pkcs7-mime" };
    char* response = NULL;
    int r =
        http_get_json(url,
                      NULL, NULL,
                      trust_store,
                      NULL, NULL, NULL,
                      headersToSend, 1,
                      &response,
                      http_retries, http_retry_delay);
    if (HTTP_CLIENT_SUCCESS != r) {
        log_error("%s::%s(%d) : Bad data received from EST endpoint", LOG_INF);
        if (response) free(response);
        return false;
    }

    log_trace("%s::%s(%d) : Preparing to decode PKCS#7 response", LOG_INF);
    pkcs7Der = base64_decode(response, strlen(response), &derLen);
    if (0 < derLen) {
        log_debug("%s::%s(%d) : PKCS#7 decoded into a DER of length %lu", LOG_INF, derLen);
        pem = ssl_convert_P7_to_pem(pkcs7Der, derLen, true);
    }

    if (pkcs7Der) free(pkcs7Der); /* no longer need this, so free as soon as not needed */

    if (pem) {
        log_debug("%s::%s(%d) : The x509 PEM is: \n%s", LOG_INF, pem);
        log_info("%s::%s(%d) : Successfully decoded PKCS#7 structure into an x.509 structure", LOG_INF);
        if (0 == replace_file(cacert_file, pem, (long)strlen(pem), true)) {
            log_info("%s::%s(%d) : Successfully wrote CA certs to store at %s", LOG_INF, cacert_file);
            result = true;
        } else {
            log_error("%s::%s(%d) : Error writing CA certs to store at %s", LOG_INF, cacert_file);
            result = false;
        }
        free(pem);
    }
    if (response) free(response);

    return result;
} /* get_ca_certs */

/**                                                                           */
/*	Process the request to the re-enrollment endpoint                         */
/*                                                                            */
/*	@param  - [Input] url = The complete url to hit                           */
/*  @param - [Output] response = the JSON response                            */
/*	@return - int response from the HTTP POST, 200 for good, else curl or     */
/*            http error code                                                 */
/*                                                                            */
static int send_reenrollment(const char* url, char** response) {
    const char* headersToSend[2] = { "Accept: */*",
                                     "Content-Transfer-Encoding: base64"};
    return http_post_json(url,
                       NULL, NULL,
                       trust_store,
                       client_cert_file, client_key_file, client_key_password,
                       csr,
                       headersToSend, 2,
                       response,
                       http_retries, http_retry_delay);
} /* send_reenrollment */

/**                                                                           */
/*	Process the request using EST Vendor mode                                 */
/*                                                                            */
/*	@param  - [Input] url = The complete url to hit                           */
/*  @param - [Output] response = the JSON response                            */
/*	@return - int response from the HTTP POST, 200 for good, else curl or     */
/*            http error code                                                 */
/*                                                                            */
static int use_est_vendor_mode(const char* url, char** response) {
    const char* headersToSend[2] = { "Accept: */*",
                                     "Content-Transfer-Encoding: base64"};
    int r;
    log_trace("%s::%s(%d) : Using EST Vendor Mode for New Device", LOG_INF);
    r = http_post_json(url,
                       NULL, NULL,
                       trust_store,
                       birth_cert_file, birth_key_file, birth_key_password,
                       csr,
                       headersToSend, 2,
                       response,
                       http_retries, http_retry_delay);
    log_debug("%s::%s(%d) : Response = \n%s", LOG_INF, *response ? *response : "null");
    return r;
} /* use_est_vendor_mode */

/**                                                                           */
/*	Process the request using EST and basic authentication                    */
/*                                                                            */
/*	@param  - [Input] url = The complete url to hit                           */
/*  @param - [Output] response = the JSON response                            */
/*	@return - int response from the HTTP POST, 200 for good, else curl or     */
/*            http error code                                                 */
/*                                                                            */
static int use_est_basic_auth(const char* url, char** response) {
    const char* headersToSend[2] = { "Accept: */*",
                                     "Content-Transfer-Encoding: base64"};
    int r;
    if (!username || !password || (0 == strlen(username)) || (0 == strlen(password)) ) {
        log_error("%s::%s(%d) : Error if we are using basic authentication, both a username "
                  "and password must be supplied", LOG_INF);
        return false;
    } else {
        log_trace("%s::%s(%d) : Using Basic Authentication for New Device", LOG_INF);
    }
    r = http_post_json(url,
                       username, password,
                       trust_store,
                       NULL, NULL, NULL,
                       csr,
                       headersToSend, 2,
                       response,
                       http_retries, http_retry_delay);
    log_debug("%s::%s(%d) : Response = \n%s", LOG_INF, *response ? *response : "null");
    return r;
} /* use_est_basic_auth */

/**                                                                           */
/*	Process the request using EST with enrollment codes in the subject or CSR */
/*                                                                            */
/*	@param  - [Input] url = The complete url to hit                           */
/*  @param - [Output] response = the JSON response                            */
/*	@return - int response from the HTTP POST, 200 for good, else curl or     */
/*            http error code                                                 */
/*                                                                            */
static int use_est_enrollment_code(const char* url, char** response) {
    const char* headersToSend[2] = { "Accept: */*",
                                     "Content-Transfer-Encoding: base64"};
    int r;
    log_trace("%s::%s(%d) : New Device using enrollment code in subject or CSR", LOG_INF);
    r = http_post_json(url,
                       NULL, NULL,
                       trust_store,
                       NULL, NULL, NULL,
                       csr,
                       headersToSend, 2,
                       response,
                       http_retries, http_retry_delay);
    log_debug("%s::%s(%d) : Response = \n%s", LOG_INF, *response ? *response : "null");
    return r;
} /* use_est_enrollment_code */

/**                                                                           */
/*	Process the request by calling the correct EST function for new enrollment*/
/*                                                                            */
/*	@param  - [Input] url = The complete url to hit                           */
/*  @param - [Output] response = the JSON response                            */
/*	@return - int response from the HTTP POST, 200 for good, else curl or     */
/*            http error code                                                 */
/*                                                                            */
static int send_enrollment(const char* url, char** response) {
    int r;

    if (!new_device) {
        log_error("%s::%s(%d) : Not set to enroll nor to reenroll, so how did we get here?", LOG_INF);
        return -999;
    }

    if (est_vendormode) {
        r = use_est_vendor_mode(url, response);
    } else if (use_basic_authentication) {
        r = use_est_basic_auth(url, response);
    } else { /* default to using the enrollment code in subject or CSR */
        r = use_est_enrollment_code(url, response);
    }

    return r;
} /* send_enrollment */

/**                                                                           */
/*	Process the response by decoding the PKCS7 package                        */
/*                                                                            */
/*	@param  - [Input] response = the JSON response                            */
/*	@return - success : true                                                  */
/*			  failure : false                                                 */
/*                                                                            */
static bool process_pkcs7_response(const char* response) {
    size_t derLen = 0;
    char* pem = NULL;
    unsigned char* pkcs7Der = NULL;
    bool result = false;

    log_trace("%s::%s(%d) : Preparing to decode PKCS#7 response", LOG_INF);
    pkcs7Der = base64_decode(response, strlen(response), &derLen);
    if (0 < derLen) {
        log_debug("%s::%s(%d) : PKCS#7 decoded into a DER of length %lu", LOG_INF, derLen);
        pem = ssl_convert_P7_to_pem(pkcs7Der, derLen, false); /* curl doesn't like non-cert data in the file */
    }

    if (pkcs7Der) free(pkcs7Der); /* no longer need this, so free as soon as not needed */

    if (pem) {
        log_debug("%s::%s(%d) : The x509 PEM is: \n%s", LOG_INF, pem);
        log_info("%s::%s(%d) : Successfully decoded PKCS#7 structure into an x.509 structure", LOG_INF);
        if (0 == save_cert_key(NULL, client_key_file, client_key_password, NULL)) {
            log_info("%s::%s(%d) : Successfully wrote client key to store at %s", LOG_INF, client_key_file);
            result = true;
        } else {
            log_error("%s::%s(%d) : Error writing client key to file system", LOG_INF);
            result = false;
        }
        if ( (result) &&
             (0 == replace_file(client_cert_file, pem, (long)strlen(pem), true)) ) {
            log_info("%s::%s(%d) : Successfully wrote client certificate to store at %s", LOG_INF, client_cert_file);
            result = true;
        } else {
            log_error("%s::%s(%d) : Error writing client certificate to store at %s", LOG_INF, client_cert_file);
            result = false;
        }
        free(pem);
    }

    return result;
} /* process_pkcs7_response */

/**                                                                           */
/*	Send a PKCS#10 request to EJBCA's EST Alias Endpoint                      */
/*                                                                            */
/*	@param  - [Input] url = The base url to hit                               */
/*  @param  - [Input] reenroll = true if we are only reenrolling              */
/*	@return - success : true                                                  */
/*			  failure : false                                                 */
/*                                                                            */
static bool send_pkcs10(const char* url, bool reenroll) {

    char* response = NULL;
    bool result = false;
    int r = 0;

    if (reenroll) {  /* reenrollment *MUST* use mTLS */
        r = send_reenrollment(url, &response);
    } else {
        r = send_enrollment(url, &response);
    }

    if (HTTP_CLIENT_SUCCESS != r) {
        log_error("%s::%s(%d) : Bad data received from EST endpoint", LOG_INF);
        if (response) free(response);
        return false;
    }

    result = process_pkcs7_response(response);

    if (response) free(response);

    return result;
} /* send_pkcs10 */

/**                                                                           */
/*	Control flow for performing EJBCA status                                  */
/*                                                                            */
/*	@return - success : true                                                  */
/*			  failure : false                                                 */
/*                                                                            */
static bool do_test_status() {
    char* url = NULL;
    if ( skip_ejbca_check ) {
        log_info("%s::%s(%d) : Input parameters successfully parsed, skipping EJBCA health check", LOG_INF);
        return true;
    }

    if ( NULL == ( url = string_cat(base_ejbca_url, ejbca_test_endpoint_url)) ) {
        log_error("%s::%s(%d) : Failed to create url for EJBCA", LOG_INF);
        return false;
    }
    bool r = test_ejbca_connection(url);
    free(url);
    if (!r) {
        log_error("%s::%s(%d) : Failed testing connection to EJBCA", LOG_INF);
        return false;
    }
    return true;

} /* do_test_status */

/**                                                                           */
/*	Control flow for fetching CA Certs                                        */
/*                                                                            */
/*	@return - success : true                                                  */
/*			  failure : false                                                 */
/*                                                                            */
static bool do_cacerts() {
    char* url = NULL;
    char* url1 = NULL;
    char* url2 = NULL;
    if ( NULL == ( url = string_cat(base_ejbca_url, ejbca_well_known)) ||
         NULL == ( url1 = string_cat(url, ejbca_est_alias) ) ||
         NULL == ( url2 = string_cat(url1, ejbca_est_cacerts_url) ) ) {
        log_error("%s::%s(%d) : Failed to create url for EJBCA", LOG_INF);
        if (url) free(url);
        if (url1) free(url1);
        if (url2) free(url2);
        return false;
    }
    free(url);
    free(url1);
    bool r = get_ca_certs(url2);
    free(url2);
    if (!r) {
        log_error("%s::%s(%d) : Failed getting or decoding CA certs from EJBCA", LOG_INF);
        return false;
    }
    return true;
} /* do_cacerts */

/**                                                                           */
/*	Set the PKCS#10 subject to be the same as the last issued client cert     */
/*                                                                            */
/*	@return - success : true                                                  */
/*			  failure : false                                                 */
/*                                                                            */
static bool use_last_subject(void) {
    bool result = false;
    if (subject) free(subject);
    subject = NULL;
    if ( NULL == (subject = ssl_get_subject(client_cert_file, MAX_SUBJECT_LEN)) ) {
        log_error("%s::%s(%d) : Error reading certificate's subject at %s", LOG_INF, client_cert_file);
        result = false;
    } else {
        log_debug("%s::%s(%d) : Found certificate subject = %s", LOG_INF, subject);
        log_debug("%s::%s(%d) : DN is now %s", LOG_INF, subject);
        result = true;
    }
    return result;
} /* use_last_subject */

/**                                                                           */
/*	Set the PKCS#10 subject use the End Entity username                       */
/*                                                                            */
/*	@return - success : true                                                  */
/*			  failure : false                                                 */
/*                                                                            */
static bool use_est_username_subject(void) {
    uint16_t subjectPtr = 0;
    subject = calloc(strlen(est_ee_username) + 4, sizeof(*subject));
    if (!subject) {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        return false;
    }
    log_trace("%s::%s(%d) : Creating subject with CN=%s", LOG_INF, est_ee_username);
    subjectPtr += sprintf(subject, "CN=%s", est_ee_username);
    if ( 0 == subjectPtr ) {
        log_error("%s::%s(%d) : Error allocating memory or generating DN", LOG_INF);
        return false;
    }
    log_debug("%s::%s(%d) : DN is now %s", LOG_INF, subject);
    return true;
} /* use_est_username_subject */

/**                                                                           */
/*	Set the PKCS#10 subject also contain the enrollment code key & value      */
/*                                                                            */
/*	@return - success : true                                                  */
/*			  failure : false                                                 */
/*                                                                            */
static bool set_subject_to_est_enrollment_code_and_key(void) {
    uint16_t subjectPtr = 0;
    uint16_t oldSubjectPtr = subjectPtr;
    log_debug("%s::%s(%d) : Adding ,%s=%s for enrollment code to subject", LOG_INF,
              est_ee_enrollmentcode_key, est_ee_enrollmentcode);
    size_t tempLen = strlen(subject)
                     + strlen(est_ee_enrollmentcode_key)
                     + strlen(est_ee_enrollmentcode)
                     + 1 /* for , */
                     + 1 /* for = */
                     + 1 /* for \0 */
    ;
    if (MAX_SUBJECT_LEN < tempLen) {
        log_error("%s::%s(%d) : Error buffer size of %u is too small for subject",
                  LOG_INF, MAX_SUBJECT_LEN);
        return false;
    }
    oldSubjectPtr = subjectPtr;
    subject = (char*)realloc(subject, tempLen);
    if (!subject) {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        return false;
    }
    subjectPtr += sprintf(subject+oldSubjectPtr, ",%s=%s",
                          est_ee_enrollmentcode_key, est_ee_enrollmentcode);
    if (oldSubjectPtr == subjectPtr) {
        log_error("%s::%s(%d) : Error adding enrollment code to DN", LOG_INF);
        return false;
    }
    log_debug("%s::%s(%d) : DN is now %s", LOG_INF, subject);
    return true;
} /* set_subject_to_est_enrollment_code_and_key */

/**                                                                           */
/*	Validate the enrollment code and key exist, because they should           */
/*                                                                            */
/*	@return - success : both the key and value (code) exist                   */
/*			  failure : otherwise                                             */
/*                                                                            */
static bool validate_enrollment_code_and_key(void) {
    bool result = true;
    if ((!est_ee_enrollmentcode) || (0 == strlen(est_ee_enrollmentcode))) {
        log_error("%s::%s(%d) : An enrollment code must be defined", LOG_INF);
        result = false;
    }
    if ((est_ee_enrollmentcode_key) && (0 < strlen(est_ee_enrollmentcode_key))) {
        log_error("%s::%s(%d) : An enrollment key field must be defined", LOG_INF);
        result = false;
    }
    return result;
} /* validate_enrollment_code_and_key */

/**                                                                           */
/*	control flow for using EST Enrollment code in the subject                 */
/*                                                                            */
/*	@return - success : true                                                  */
/*			  failure : false                                                 */
/*                                                                            */
static bool use_est_enrollment_code_subject(void) {
    bool result = false;
    log_debug("%s::%s(%d) : DN is now %s", LOG_INF, subject);
    if (validate_enrollment_code_and_key()) {
        result = set_subject_to_est_enrollment_code_and_key();
        log_debug("%s::%s(%d) : DN is now %s", LOG_INF, subject);
    } else {
        log_error("%s::%s(%d) : An enrollment code must be defined", LOG_INF);
        result = false;
    }
    return result;
} /* use_est_enrollment_code_subject */

/**                                                                           */
/* Set the subject for the CSR based on the parameters used                   */
/*                                                                            */
/*	@return - success : true                                                  */
/*			  failure : false                                                 */
/*                                                                            */
static bool set_subject(bool reenroll) {

    if ( reenroll ) { /* Use the subject of the last certificate */
        return use_last_subject();
    }

    if (subject_supplied_on_command_line) { /* This overrides any supplied username/enrollmentcode */
        log_debug("%s::%s(%d) : Subject was supplied on the command line as %s", LOG_INF, subject);
        return true;
    }

    if ((est_ee_username) && (0 < strlen((est_ee_username)))) {  /* Set the username as the CN */
        return use_est_username_subject();
    } else {
        log_error("%s::%s(%d) : A username must be defined!", LOG_INF);
        return false;
    }

    /* If we are using a vendor certificate or challenge password, or we are using basic auth, */
    /* then don't modify the subject */
    if ( est_vendormode || use_challenge_password || username  || password ) {
        return true;
    }

    /* If we aren't using a vendor certificate, and we aren't using a challenge password, */
    /* and we are not using basic auth, then we need an enrollment code in the subject    */
    return use_est_enrollment_code_subject();

} /* set_subject */

/**                                                                           */
/*	Set the full URL to use when talking to EJBCA                             */
/*                                                                            */
/*  @param  - [Input] reenroll = true if we are only doing a reenrollment     */
/*                               false if this is a new device                */
/*	@return - success : the full URL to use                                   */
/*			  failure : NULL                                                  */
/*                                                                            */
static char* set_url(bool reenroll) {
    char* url1 = NULL;
    char* url2 = NULL;
    char* url3 = NULL;

    if (NULL == (url1 = string_cat(base_ejbca_url, ejbca_well_known)) ||
        NULL == (url2 = string_cat(url1, ejbca_est_alias)) ) {
        goto exit;
    }

    if (reenroll) {
        url3 = string_cat(url2, ejbca_est_simplereenroll_url);
    } else {
        url3 = string_cat(url2, ejbca_est_simpleenroll_url);
    }

exit:
    if (url1) free(url1);
    if (url2) free(url2);
    if (!url3) {
        log_error("%s::%s(%d) : Failed to create url for EJBCA", LOG_INF);
    }
    return url3;
} /* set_url */

/**                                                                           */
/*	Control flow for sending an EST enrollment request                        */
/*                                                                            */
/*	@return - success : true                                                  */
/*			  failure : false                                                 */
/*                                                                            */
static bool do_csr(bool reenroll) {

    if ( !set_subject(reenroll) )
        return false;

    log_info("%s::%s(%d) : Generating keypair of type %s and size %d", LOG_INF, key_type, key_size);
    if ( !generate_keypair(key_type, key_size) ) {
        log_error("%s::%s(%d) : Failed to generate keypair", LOG_INF);
        return false;
    }
    log_trace("%s::%s(%d) : Successfully generated keypair of type %s and size %d", LOG_INF, key_type, key_size);

#ifdef __ALLOW_NAME_CHANGE__
    if ( est_vendormode && alt_subject_name ) {
        /* Now set the csr subject to the end entity to the new subject & pass in subject for the change name attribute */
        if (NULL == (csr = generate_csr(subject, &csr_len,
                                        use_challenge_password, challenge_password, subject, allow_name_change))) {
            log_error("%s::%s(%d) : Failed to generate CSR", LOG_INF);
            return false;
        }
    } else {
        if (NULL == (csr = generate_csr(subject, &csr_len,
                                        use_challenge_password, challenge_password, NULL, allow_name_change))) {
            log_error("%s::%s(%d) : Failed to generate CSR", LOG_INF);
            return false;
        }
    }
#else
    if (NULL == (csr = generate_csr(subject, &csr_len,use_challenge_password, challenge_password))) {
        log_error("%s::%s(%d) : Failed to generate CSR", LOG_INF);
        return false;
    }
#endif

    log_debug("%s::%s(%d) : Successfully generated CSR = \n%s", LOG_INF, csr);
    log_info("%s::%s(%d) : Successfully created CSR with subject %s", LOG_INF, subject);

    char* url = set_url(reenroll);
    if (!url) {
        if (csr) free(csr);
        csr = NULL;
        return false;
    }

    bool r = send_pkcs10(url, reenroll);
    if (!r) {
        log_error("%s::%s(%d) : Failed to get a certificate", LOG_INF);
        if (csr) free(csr);
        csr = NULL;
        free(url);
        return false;
    }
    free(url);

    return true;
} /* do_csr */

/**                                                                           */
/*	Free all dynamically allocated memory                                     */
/*                                                                            */
/*	@return - nothing                                                         */
/*                                                                            */
static void free_memory() { /* parasoft-suppress METRICS-44 "Freeing Memory must check for NULL" */
    if (ejbca_est_alias) free(ejbca_est_alias);
    if (birth_cert_file) free(birth_cert_file);
    if (cacert_file) free (cacert_file);
    if (birth_key_file) free(birth_key_file);
    if (client_cert_file) free(client_cert_file);
    if (client_key_password) free(client_key_password);
    if (key_type) free(key_type);
    if (password) free(password);
    if (subject) free(subject);
    if (trust_store) free(trust_store);
    if (username) free(username);
    if (base_ejbca_url) free(base_ejbca_url);
    if (est_ee_username) free(est_ee_username);
    if (est_ee_enrollmentcode_key) free(est_ee_enrollmentcode_key);
    if (est_ee_enrollmentcode) free(est_ee_enrollmentcode);
    if (challenge_password) free(challenge_password);
    if (csr) free(csr);

    /* For re-entrant library code */
    ejbca_est_alias = NULL;
    birth_cert_file = NULL;
    cacert_file = NULL;
    birth_key_file = NULL;
    client_cert_file = NULL;
    client_key_password = NULL;
    key_type = NULL;
    password = NULL;
    subject = NULL;
    trust_store = NULL;
    username = NULL;
    base_ejbca_url = NULL;
    est_ee_username = NULL;
    est_ee_enrollmentcode_key = NULL;
    est_ee_enrollmentcode = NULL;
    challenge_password = NULL;
    csr = NULL;
} /* free_memory() */

/**                                                                           */
/*	Control flow for processing the command line switches                     */
/*                                                                            */
/*	@return - nothing                                                         */
/*                                                                            */
static void do_parameters(int argc, char* argv[]) {
    /* Parse command line switches & perform a sanity check on the values    */
    /* Code can be shrunk by removing this validation step                   */
    bool parameterParsingResult = parse_parameters(argc, argv);
    if (parameterParsingResult) {
        if ( validate_parameters(argv[0]) ) {
            if (print_usage_only) {
                free_memory();
                exit(EXIT_SUCCESS);
            }
        } else {
            free_memory();
            printf("FAILED to validate input parameters\n");
            exit(EXIT_FAILURE);
        }
    } else {
        free_memory();
        printf("FAILED to parse input parameters\n");
        exit(EXIT_FAILURE);
    }

    /* Check to see if the -r and -n switches were used.  If neither was set, assume new device. */
    if (!reenroll_only && !new_device) {
        new_device = true;
    }

    return;
} /* do_parameters */

/**                                                                           */
/*	Control flow for a new device                                             */
/*                                                                            */
/*	@return - sucess : true                                                   */
/*            failure: false                                                  */
/*                                                                            */
static bool do_est_new_device(void) {
    log_info("%s::%s(%d) : Getting CA certs from EST Alias", LOG_INF);
    if (!do_cacerts()) {
        return false;
    }

    log_info("%s::%s(%d) : Generating CSR for submittal to endpoint", LOG_INF);
    if (!do_csr(false)) {
        return false;
    }

    return true;
} /* do_est_new_device */

/**                                                                           */
/*	Control flow for an existing device's re-enrollment                       */
/*                                                                            */
/*	@return - sucess : true                                                   */
/*            failure: false                                                  */
/*                                                                            */
static bool do_est_reenroll_only(void) {
    log_info("%s::%s(%d) : Generating re-enrollment for submittal to endpoint", LOG_INF);
    if (!do_csr(true)) {
        return false;
    }
    return true;
} /* do_est_reenroll_only */

/**                                                                           */
/*	Control flow for performing the EST function                              */
/*                                                                            */
/*	@return - sucess : true                                                   */
/*            failure: false                                                  */
/*                                                                            */
static bool do_est_function(void) {
    bool result = true;
    if ( new_device ) {
        result = do_est_new_device();
    } else if ( reenroll_only ) {
        result = do_est_reenroll_only();
    } else {
        log_error("%s::%s(%d) : We should never get here", LOG_INF);
        result = false;
    }
    return result;
} /* do_est_function */

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/*	Main program entry point                                                  */
/*                                                                            */
/* If we want to use #define defaults, copy them using set_defaults()         */
/* If, instead, the desire is to always use command line switches, then       */
/* The code size can be minimized by removing this and the #defines           */
/* Another option is to use a configuration json file (since a JSON)          */
/* library is already used by EST                                             */
/*                                                                            */
/* This library is an example of *ALL* possible enrollment capabilities that  */
/* EJBCA implements using EST.  This example library can be used as a starting*/
/* point to generate a complete EST library by customizing it to the use case */
/*                                                                            */
/* That is a programmer can eliminate unused use cases & implement the passing*/
/* of parameters as the IoT device sees fit.                                  */
/*                                                                            */
int main(int argc, char* argv[]) {
    if ( !set_defaults() ) exit(EXIT_FAILURE);
    ssl_init();
    do_parameters(argc, argv);
    log_info("%s::%s(%d) : Input parameters successfully parsed, testing EJBCA status", LOG_INF);
    if (!do_test_status())  goto exit_failure;
    if (!do_est_function()) goto exit_failure;

    ssl_cleanup();
    log_info("%s::%s(%d) : Successfully finished client", LOG_INF);
    free_memory();
    exit(EXIT_SUCCESS);

exit_failure:
    ssl_cleanup();
    log_error("%s::%s(%d) : Exiting with FAILURE", LOG_INF);
    free_memory();
    exit(EXIT_FAILURE);

} /* main */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/
