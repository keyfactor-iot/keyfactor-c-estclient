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
#define _CRT_SECURE_NO_WARNINGS

#include "../include/logging.h"
#include "../include/file_utilities.h"
#include "../include/httpclient.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

/******************************************************************************/
/***************************** GLOBAL VARIABLES *******************************/
/******************************************************************************/

/******************************************************************************/
/***************************** LOCAL DEFINES  *********************************/
/******************************************************************************/
#define CONNECTION_TIMEOUT 60

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/
/**                                                                           */
/* The memory structure used by curl in its callback function                 */
/* memory holds the curl response data (callback NULL terminates this data)   */
/* size holds the size of the data                                            */
/*                                                                            */
struct MemoryStruct {
  char *memory;
  size_t size;
};

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/
unsigned char* client_cert_compressed = NULL;

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/* The memory callback function curl uses -- the default is fwrite, so we     */
/* want to change that behaviour.                                             */
/*                                                                            */
/* to send data to this function, execute:                                    */
/*  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback) */
/*                                                                            */
/* to pass our 'chunk' structure we need this code:                           */
/*  struct MemoryStruct chunk;                                                */
/*  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);         */
/*                                                                            */
/* This function gets called by libcurl as soon as there is data received     */
/* that needs to be saved.  For most transfers, this callback gets called many*/
/* times and each invoke delivers another chunk of data.                      */
/*                                                                            */
/* @param  - [Output] contents = The delivered data (NOT NULL TERMINATED)     */
/* @param  - [N/A] size = 1.  This is always one (refers to a byte)           */
/* @param  - [Input] nmemb = The size of the delivered contents               */
/* @param  - [Output] userp =                                                 */
/* @return - success = the number of bytes taken care of                      */
/*           failure = the number of bytes taken care of                      */
/*                                                                            */
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  mem->memory = realloc( mem->memory, (mem->size + realsize + 1) );
  if( NULL == mem->memory )  {
    log_error("%s::%s(%d): out of memory", LOG_INF);
    return 0;
  } else {
      log_trace("%s::%s(%d) : chunk memory of %lu bytes allocated", LOG_INF, (mem->size + realsize + 1));
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = '\0';

  return realsize;
} /* WriteMemoryCallback */

/**                                                                           */
/*  Add information required to establish an mTLS session with CURL           */
/*                                                                            */
/*   @param curl = a Pointer to a curl session                                */
/*   @param clientCert = a string with a filename containing a CA signed      */
/*                       cert for this platform (for TLS communication)       */
/*   @param clientKey = a string with a filename containing the private key   */
/*                      associated with the clientCert                        */
/*   @param clientKeyPass = a string with the password associated with the    */
/*                          clientKey                                         */
/*                                                                            */
static void add_mTLS(CURL* curl,
                     const char* clientCert,
                     const char* clientKey,
                     const char* clientKeyPass) {
    size_t dummySize = 0;
    do {
        if (false == file_exists(clientCert) ||
            false == file_exists(clientKey)) {
            log_warn("%s::%s(%d) : Either a client cert at %s or client key at %s does not exist, bypassing",
                     LOG_INF, clientCert, clientKey);
            break;
        }

        /* We have both the filenames and the files exist for the clientCert and clientKey */
        log_trace("%s::%s(%d) : Setting clientCert to %s", LOG_INF, clientCert);
        (void) curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
        (void) curl_easy_setopt(curl, CURLOPT_SSLCERT, clientCert);
        read_file_bytes(clientCert, &client_cert_compressed, &dummySize);
        if (NULL == client_cert_compressed) {
            log_error("%s::%s(%d) : Out of memory copying client certificate", LOG_INF);
            break;
        }

        log_trace("%s::%s(%d) : Setting clientKey to %s", LOG_INF, clientKey);
        (void) curl_easy_setopt(curl, CURLOPT_SSLKEY, clientKey);
        if (clientKeyPass) {
            log_trace("%s::%s(%d) : Setting clientPassword", LOG_INF);
            (void) curl_easy_setopt(curl, CURLOPT_KEYPASSWD, clientKeyPass);
        }

    } while(false);

    return;
} /* add_mTLS */

/**                                                                           */
/*  Setup common parameters used in curl functions                            */
/*                                                                            */
/*   @param curl = a Pointer to a curl session                                */
/*   @param url = a string with the URL address to contact                    */
/*   @param username = a string with the username to log into the URL address */
/*   @param password = a string with password to log into the URL address     */
/*   @param trustStore = a string with a filename containing additional       */
/*                       trusted certificates                                 */
/*   @param clientCert = a string with a filename containing a CA signed      */
/*                       cert for this platform (for TLS communication)       */
/*   @param clientKey = a string with a filename containing the private key   */
/*                      associated with the clientCert                        */
/*   @param clientKeyPass = a string with the password associated with the    */
/*                          clientKey                                         */
/*   @return none                                                             */
/*                                                                            */
static void common_curl_setup(CURL* curl,
                              const char* url,
                              const char* username,
                              const char* password,
                              const char* trustStore,
                              const char* clientCert,
                              const char* clientKey,
                              const char* clientKeyPass) {

    char errBuff[CURL_ERROR_SIZE];

    /**************************************************************************/
    /*  Set up curl to point to a url using the username and Password         */
    /*  passed to the function                                                */
    /**************************************************************************/
    if ( username && password && (1 < strlen(username)) && (1 < strlen(password)) ) {
        log_trace("%s::%s(%d) : Configuring username and password", LOG_INF);
        (void)curl_easy_setopt(curl, CURLOPT_USERNAME, username);
        (void)curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
    } else {
        log_trace("%s::%s(%d) : Username and password not supplied - skipping", LOG_INF);
    }

    log_trace("%s::%s(%d) : Configuring url = %s", LOG_INF, url);
    (void)curl_easy_setopt(curl, CURLOPT_URL, url);

    log_trace("%s::%s(%d) : Setting CURL connection timeout to %d seconds", LOG_INF, CONNECTION_TIMEOUT);
    (void)curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECTION_TIMEOUT);

    log_trace("%s::%s(%d) : Allowing cURL to follow redirects", LOG_INF);
    (void)curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    /**************************************************************************/
    /*  If the passed files exist in the system, then use them for additional */
    /*  trusted certificates, and certs to create the TLS connection.         */
    /**************************************************************************/
    if( file_exists(trustStore) ) {
        log_trace("%s::%s(%d) : Setting trustStore to %s", LOG_INF, trustStore);
        (void) curl_easy_setopt(curl, CURLOPT_CAINFO, trustStore);
    } else {
        log_trace("%s::%s(%d) : Trust store does not exist", LOG_INF);
    }

    if ( !clientCert || !clientKey ) {
        log_debug("%s::%s(%d) : No client cert or no client key file was specified, not adding mTLS", LOG_INF);
    } else {
        /* We have a filename for both the clientCert and clientKey, so try and add them */
        log_trace("%s::%s(%d) : Adding mTLS to curl", LOG_INF);
        add_mTLS(curl, clientCert, clientKey, clientKeyPass);
    }

    /* Turn on verbose output for tracing */
    if ( is_log_trace() ) {
        log_trace("%s::%s(%d) : Turning on cURL verbose output", LOG_INF);
        (void)curl_easy_setopt( curl, CURLOPT_VERBOSE, 1 );
        (void)curl_easy_setopt( curl, CURLOPT_ERRORBUFFER, errBuff );
        errBuff[0] = 0; /* empty the error buffer */
    }

    /* send all data to this function  */
    (void)curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

    return;
} /* common_curl_setup */

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/*  Issue an HTTP POST command stating that the content is JSON and that a    */
/*   JSON response is accepted.                                               */
/*                                                                            */
/*   @param url = a string with the URL address to contact                    */
/*   @param username = a string with the username to log into the URL address */
/*   @param password = a string with password to log into the URL address     */
/*   @param trustStore = a string with a filename containing additional       */
/*                       trusted certificates                                 */
/*   @param clientCert = a string with a filename containing a CA signed      */
/*                       cert for this platform (for TLS communication)       */
/*   @param clientKey = a string with a filename containing the private key   */
/*                      associated with the clientCert                        */
/*   @param clientKeyPass = a string with the password associated with the    */
/*                          clientKey                                         */
/*   @param postData = a JSON string                                          */
/*   @param pRespData = a pointer to a string where the HTTP response         */
/*                      data gets set.  NOTE: This memory gets DYNAMICALLY    */
/*                      allocated here!  You need to properly dispose of it in*/
/*                      the calling function.                                 */
/*   @param retryCount = The number of times to try the http session          */
/*   @param retryInterval = The time (in seconds) between retries             */
/*   @return 0 on successfull completion                                      */
/*           1-99 corresponding to the failed cURL response code              */
/*           255 if the dynamic memory allocation for pRespData fails         */
/*           300-511 The HTTP response error (e.g. 404 Not Found)             */
/*                                                                            */
int http_post_json(const char* url, const char* username,
                   const char* password, const char* trustStore,
                   const char* clientCert, const char* clientKey,
                   const char* clientKeyPass, char* postData,
                   const char* headers[], const unsigned int headerCount,
                   char** pRespData, int retryCount, int retryInterval) {

    log_debug("%s::%s(%d) : Preparing to POST to %s", LOG_INF, url);
    if (is_log_trace()) {
        log_trace("%s::%s(%d) : url           = %s", LOG_INF, NULL == url ? "null" : url);
        log_trace("%s::%s(%d) : username      = %s", LOG_INF, NULL == username ? "null" : username);
        log_trace("%s::%s(%d) : password      = %s", LOG_INF, NULL == password ? "null" : password);
        log_trace("%s::%s(%d) : trustStore    = %s", LOG_INF, NULL == trustStore ? "null" : trustStore);
        log_trace("%s::%s(%d) : clientCert    = %s", LOG_INF, NULL == clientCert ? "null" : clientCert);
        log_trace("%s::%s(%d) : clientKey     = %s", LOG_INF, NULL == clientKey ? "null" : clientKey);
        log_trace("%s::%s(%d) : clientKeyPass = %s", LOG_INF, NULL == clientKeyPass ? "null" : clientKeyPass);
        log_trace("%s::%s(%d) : postData     =\n%s", LOG_INF, NULL == postData ? "null" : postData);
        for (unsigned int i = 0; headerCount > i; i++) {
            log_trace("%s::%s(%d) : headers[%d]   = %s", LOG_INF, i, NULL == headers[i] ? "null" : headers[i]);
        }
        log_trace("%s::%s(%d) : headerCount   = %d", LOG_INF, headerCount);
        log_trace("%s::%s(%d) : pRespData     = %p", LOG_INF, pRespData);
        log_trace("%s::%s(%d) : *pRespData    = %s", LOG_INF, NULL == *pRespData ? "null" : *pRespData);
        log_trace("%s::%s(%d) : retryCount    = %d", LOG_INF, retryCount);
        log_trace("%s::%s(%d) : retryInterval = %d", LOG_INF, retryInterval);
    }

	int toReturn = -1;
    log_trace("%s::%s(%d) : Initializing cURL", LOG_INF);
	CURL* curl = curl_easy_init();

    if (!curl) return toReturn; /* Error out if curl doesn't get initialized */

    log_trace("%s::%s(%d) : Curl initialized ok, allocating chunk memory", LOG_INF);
    struct MemoryStruct chunk;
    chunk.size = 0;
    chunk.memory = calloc(1,sizeof(*chunk.memory));
    if ( !chunk.memory ) {
      log_error("%s::%s(%d): Out of memory when allocating chunk", LOG_INF);
      curl_easy_cleanup(curl);
      return CURLE_FAILED_INIT;
    }
    log_trace("%s::%s(%d) : Successfully allocated chunk memory", LOG_INF);
    /* we pass our 'chunk' struct to the callback function */
    (void)curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    /* Setup all the common data */
    common_curl_setup(curl, url, username, password, trustStore, clientCert, clientKey, clientKeyPass);

    /* Set the method to POST */
    log_trace("%s::%s(%d) : Setting curl to POST", LOG_INF);
    (void)curl_easy_setopt(curl, CURLOPT_POST, 1L);

    log_trace("%s::%s(%d) : cURL options set correctly", LOG_INF);

    struct curl_slist* list = NULL;
    /**************************************************************************/
    /*    Set up the HTTP header to tell the API this is standard JSON.       */
    /*    NOTE: Some versions of Internet Explorer have a problem using       */
    /*          these headers.                                                */
    /*    Also, set the content length header option to the data size.        */
    /**************************************************************************/
/*    list = curl_slist_append(NULL, "Content-Type: application/json");
    list = curl_slist_append(list, "Accept: application/json");*/
    /* For a POST, we need to always add the Context-Length: header */
    char clBuf[30];
    (void)snprintf(clBuf, 30, "Content-Length: %d", (int)strlen(postData));
    list = curl_slist_append(NULL, clBuf);
    /* Add any passed headers */
    for (size_t index = 0; headerCount > index; index++) {
        list = curl_slist_append(list, headers[index]);
    }


    /**************************************************************************/
    /*  Now add the header & data to the HTTP POST request.                   */
    /**************************************************************************/
    (void)curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    (void)curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData);
    (void)curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (int)strlen(postData));
    log_trace("%s::%s(%d): postData =\n%s", LOG_INF, postData);


    /**************************************************************************/
    /*  Make sure the cURL operation succeeded and the HTTP response code     */
    /*  indicates success. If we are successfull, place the response message  */
    /*  If the cURL operation fails, return the cURL error code.              */
    /*  If the HTTP response is an error, return the HTTP failure code.       */
    /**************************************************************************/
    long httpCode = 0;
    int res = CURLE_FAILED_INIT;
    int tries = retryCount;

    while (0 < tries) {
      res = curl_easy_perform(curl);
      (void)curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &httpCode);
      /* if there was an error & we still have tries left to do */
      tries--;
      log_verbose("%s::%s(%d): curl resp = %d, httpCode = %ld, tries left = %d",
        LOG_INF,res, httpCode, tries);
      if(((CURLE_OK != res) || (httpCode >= 300)) && (0 < tries)) {
        log_verbose("%s::%s(%d): Failed curl post. Sleeping %d seconds before retry", LOG_INF,retryInterval);
        if ( 0 < retryInterval ) {
          (void)sleep((unsigned int)retryInterval);
        }
      } else {
        tries = 0; /* exit the loop */
      }
    } /* while */

    if(res != CURLE_OK) {
        /* When tracing, dump the error buffer to stderr */
        if ( is_log_trace() ) {
            char errBuff[CURL_ERROR_SIZE];
            size_t len = strlen( errBuff );
            log_error( "%s::%s(%d): libcurl: (%d) ", LOG_INF, res );
            if ( 0 != len ) {
                log_error( "%s::%s(%d): %s%s", LOG_INF,	errBuff,((errBuff[len-1] != '\n') ? "\n" : ""));
            } else {
                log_error("%s::%s(%d): %s\n", LOG_INF, curl_easy_strerror(res) );
            }
        }
        log_error("%s::%s(%d): %s", LOG_INF, curl_easy_strerror(res));
        toReturn = res;
    } else if(httpCode >= 300) {
        log_error("%s::%s(%d): HTTP Response: %ld", LOG_INF, httpCode);
        toReturn = (int)httpCode;
    } else {
        log_verbose("%s::%s(%d): %lu bytes retrieved -- allocating memory for response",
                    LOG_INF, (unsigned long)chunk.size);
        if (0 < chunk.size) {
            log_debug("%s::%s(%d) : Response is:\n%s", LOG_INF, chunk.memory);
            log_trace("%s::%s(%d) : Allocating memory for the response", LOG_INF);
            *pRespData = calloc(chunk.size+1, sizeof(char));
            log_trace("%s::%s(%d) : Successfully allocated %lu bytes of memory for response", LOG_INF, chunk.size+1);
            if ( NULL == pRespData ) {
                log_error("%s::%s(%d) : Out of memory", LOG_INF);
                toReturn = 255;
            } else {
                *pRespData = memcpy(*pRespData, chunk.memory, chunk.size);
                log_trace("%s::%s(%d): Response to pass back is:\n%s", LOG_INF, *pRespData);
                toReturn = 0;
            }
        } else {
            log_trace("%s::%s(%d): Zero length response retrieved", LOG_INF);
            toReturn = 0;
        }

        /* Cleanup, de-allocate, etc. */
        if (list) {
            curl_slist_free_all(list);
        }
        if (curl) {
            curl_easy_cleanup(curl);
        }
        if (chunk.memory) {
            free(chunk.memory);
        }
        if (client_cert_compressed) {
            free(client_cert_compressed);
            client_cert_compressed = NULL;
        }
    }

	return toReturn;
} /* http_post_json */

/**                                                                           */
/*  Issue an HTTP POST command stating that the content is JSON and that a    */
/*   JSON response is accepted.                                               */
/*                                                                            */
/*   @param url = a string with the URL address to contact                    */
/*   @param username = a string with the username to log into the URL address */
/*   @param password = a string with password to log into the URL address     */
/*   @param trustStore = a string with a filename containing additional       */
/*                       trusted certificates                                 */
/*   @param clientCert = a string with a filename containing a CA signed      */
/*                       cert for this platform (for TLS communication)       */
/*   @param clientKey = a string with a filename containing the private key   */
/*                      associated with the clientCert                        */
/*   @param clientKeyPass = a string with the password associated with the    */
/*                          clientKey                                         */
/*   @param postData = a JSON string                                          */
/*   @param pRespData = a pointer to a string where the HTTP response         */
/*                      data gets set.  NOTE: This memory gets DYNAMICALLY    */
/*                      allocated here!  You need to properly dispose of it in*/
/*                      the calling function.                                 */
/*   @param retryCount = The number of times to try the http session          */
/*   @param retryInterval = The time (in seconds) between retries             */
/*   @return 0 on successfull completion                                      */
/*           1-99 corresponding to the failed cURL response code              */
/*           255 if the dynamic memory allocation for pRespData fails         */
/*           300-511 The HTTP response error (e.g. 404 Not Found)             */
/*                                                                            */
int http_get_json(const char* url, const char* username,
                   const char* password, const char* trustStore,
                   const char* clientCert, const char* clientKey,
                   const char* clientKeyPass, const char* headers[], const unsigned int headerCount,
                   char** pRespData, int retryCount, int retryInterval)
{
    log_debug("%s::%s(%d) : Preparing to GET from %s", LOG_INF, url);
    if (is_log_trace()) {
        log_trace("%s::%s(%d) : url           = %s", LOG_INF, NULL == url ? "null" : url);
        log_trace("%s::%s(%d) : username      = %s", LOG_INF, NULL == username ? "null" : username);
        log_trace("%s::%s(%d) : password      = %s", LOG_INF, NULL == password ? "null" : password);
        log_trace("%s::%s(%d) : trustStore    = %s", LOG_INF, NULL == trustStore ? "null" : trustStore);
        log_trace("%s::%s(%d) : clientCert    = %s", LOG_INF, NULL == clientCert ? "null" : clientCert);
        log_trace("%s::%s(%d) : clientKey     = %s", LOG_INF, NULL == clientKey ? "null" : clientKey);
        log_trace("%s::%s(%d) : clientKeyPass = %s", LOG_INF, NULL == clientKeyPass ? "null" : clientKeyPass);
        for (unsigned int i = 0; headerCount > i; i++) {
            log_trace("%s::%s(%d) : headers[%d]   = %s", LOG_INF, i, NULL == headers[i] ? "null" : headers[i]);
        }
        log_trace("%s::%s(%d) : headerCount   = %d", LOG_INF, headerCount);
        log_trace("%s::%s(%d) : pRespData     = %p", LOG_INF, pRespData);
        log_trace("%s::%s(%d) : *pRespData    = %s", LOG_INF, NULL == *pRespData ? "null" : *pRespData);
        log_trace("%s::%s(%d) : retryCount    = %d", LOG_INF, retryCount);
        log_trace("%s::%s(%d) : retryInterval = %d", LOG_INF, retryInterval);
    }


    int toReturn = -1;
    log_trace("%s::%s(%d) : Initializing cURL", LOG_INF);
    CURL* curl = curl_easy_init();
    char errBuff[CURL_ERROR_SIZE];

    if (!curl) return toReturn; /* Error out if curl doesn't get initialized */

    log_trace("%s::%s(%d) : Curl initialized ok, allocating chunk memory", LOG_INF);
    struct MemoryStruct chunk;
    chunk.size = 0;
    chunk.memory = calloc(1,sizeof(*chunk.memory));
    if ( !chunk.memory ) {
        log_error("%s::%s(%d): Out of memory when allocating chunk", LOG_INF);
        curl_easy_cleanup(curl);
        return CURLE_FAILED_INIT;
    }
    log_trace("%s::%s(%d) : Successfully allocated chunk memory", LOG_INF);
    /* we pass our 'chunk' struct to the callback function */
    (void)curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    /* Setup all the common data */
    common_curl_setup(curl, url, username, password, trustStore, clientCert, clientKey, clientKeyPass);

    /* Set the method to GET */
    log_trace("%s::%s(%d) : Setting curl to GET", LOG_INF);
    (void)curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

    log_trace("%s::%s(%d) : cURL options set correctly", LOG_INF);


    /* Add any passed headers */
    struct curl_slist* list = NULL;
    for (size_t index = 0; headerCount > index; index++) {
        list = curl_slist_append(list, headers[index]);
    }
    (void)curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);


    /**************************************************************************/
    /*  Make sure the cURL operation succeeded and the HTTP response code     */
    /*  indicates success. If we are successfull, place the response message  */
    /*  If the cURL operation fails, return the cURL error code.              */
    /*  If the HTTP response is an error, return the HTTP failure code.       */
    /**************************************************************************/
    long httpCode = 0;
    int res = CURLE_FAILED_INIT;
    int tries = retryCount;

    while (0 < tries) {
        res = curl_easy_perform(curl);
        (void)curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &httpCode);
        /* if there was an error & we still have tries left to do */
        tries--;
        log_verbose("%s::%s(%d): curl resp = %d, httpCode = %ld, tries left = %d", LOG_INF,res, httpCode, tries);
        if(((CURLE_OK != res) || (httpCode >= 400)) && (0 < tries)) {
            log_verbose("%s::%s(%d): Failed curl post. Sleeping %d seconds before retry", LOG_INF,retryInterval);
            if ( 0 < retryInterval ) (void)sleep((unsigned int)retryInterval);
        } else {
            tries = 0; /* exit the loop */
        }
    } /* while */

    if(res != CURLE_OK) {
        /* When tracing, dump the error buffer to stderr */
        if ( is_log_trace() ) {
            size_t len = strlen( errBuff );
            log_error( "%s::%s(%d): libcurl: (%d) ", LOG_INF, res );
            if ( 0 != len ) {
                log_error( "%s::%s(%d): %s%s", LOG_INF, errBuff,((errBuff[len-1] != '\n') ? "\n" : ""));
            } else {
                log_error("%s::%s(%d): %s\n", LOG_INF, curl_easy_strerror(res) );
            }
        }
        log_error("%s::%s(%d): %s", LOG_INF, curl_easy_strerror(res));
        toReturn = res;
    } else if(httpCode >= 300) {
        log_error("%s::%s(%d): HTTP Response: %ld", LOG_INF, httpCode);
        toReturn = (int)httpCode;
    } else {
        log_verbose("%s::%s(%d) : %lu bytes retrieved", LOG_INF, (unsigned long)chunk.size);
        if (0 < chunk.size) {
            log_debug("%s::%s(%d) : Response is:\n%s", LOG_INF, chunk.memory);
            log_trace("%s::%s(%d) : Allocating memory for the response", LOG_INF);
            *pRespData = calloc(chunk.size+1, sizeof(char));
            log_trace("%s::%s(%d) : Successfully allocated %lu bytes of memory for response", LOG_INF, chunk.size+1);
            if ( NULL == pRespData ) {
                log_error("%s::%s(%d) : Out of memory", LOG_INF);
                toReturn = 255;
            } else {
                *pRespData = memcpy(*pRespData, chunk.memory, chunk.size);
                log_trace("%s::%s(%d): Response to pass back is:\n%s", LOG_INF, *pRespData);
                toReturn = 0;
            }
        } else {
            log_trace("%s::%s(%d): Zero length response retrieved", LOG_INF);
            toReturn = 0;
        }

        /* Cleanup, de-allocate, etc. */
        if (list) {
            curl_slist_free_all(list);
        }
        if (curl) {
            curl_easy_cleanup(curl);
        }
        if (chunk.memory) {
            free(chunk.memory);
        }
        if (client_cert_compressed) {
            free(client_cert_compressed);
            client_cert_compressed = NULL;
        }
    }

    return toReturn;
} /* http_get_json */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/