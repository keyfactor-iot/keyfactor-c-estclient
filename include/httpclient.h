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

#ifndef __HTTPCLIENT_H__
#define __HTTPCLIENT_H__

/**************************************************************************/
/******************* GLOBAL FUNCTION PROTOTYPES ***************************/
/**************************************************************************/
int http_post_json(const char* url, const char* _username, const char* _password,
                   const char* trustStore, const char* clientCert, const char* clientKey,
                   const char* clientKeyPass, char* postData,
                   const char* headers[], const unsigned int headerCount,
                   char** pRespData, int retryCount, int retryInterval);

int http_get_json (const char* url, const char* _username, const char* _password,
                   const char* trustStore, const char* clientCert, const char* clientKey,
                   const char* clientKeyPass, const char* headers[], const unsigned int headerCount,
                   char** pRespData, int retryCount,  int retryInterval);

#endif /* __HTTPCLIENT_H__ */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/