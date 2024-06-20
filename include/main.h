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

#ifndef __MAIN_H__
#define __MAIN_H__

#include <stdint.h>
#include <stdbool.h>

/**                                                                            */
/* Revision History:                                                           */
/*  0.15.0.0 = Initial version supporting OpenSSL 1.1.x final testing required */
/*  1.0.0.0  = Initial version using OpenSSL 1.1.x.                            */
/*                                                                             */
#define PROGRAM_VERSION 0x0001000000000000UL

/**************************************************************************/
/************************* GLOBAL DEFINES *********************************/
/**************************************************************************/
#define MAX_ALIAS_LEN           64
#define MAX_CACERTS_NAME        128
#define MAX_BIRTHCERT_NAME      128
#define MAX_BIRTHKEY_NAME       128
#define MAX_BIRTHKEY_PASS_LEN   64
#define MAX_CLIENTCERT_NAME     128
#define MAX_CLIENTKEY_NAME      128
#define MAX_TRUST_STORE_NAME    128
#define MAX_CLIENTPASS_NAME     64
#define MAX_KEY_TYPEVAR         3
#define MAX_KEYSIZE_LEN         4
#define MAX_PASSWORD_LEN        64
#define MAX_SUBJECT_LEN         1024
#define MAX_BASE_URL_LEN        128
#define MAX_USERNAME_LEN        64
#define MAX_ENROLLMENT_USER_LN  64
#define MAX_ENROLLMENT_KEY_LEN  2
#define MAX_ENROLLMENT_CODE_LEN 64

#define NUM_ECC_KEY_SIZES       3
#define NUM_RSA_KEY_SIZES       7

#define HTTP_CLIENT_SUCCESS     0

/**************************************************************************/
/****************** SHARED VARIABLES FOR OPTIONS **************************/
/**************************************************************************/
/* Variables we share with the options file */
extern char* ejbca_est_alias;
extern char* birth_cert_file;
extern char* cacert_file;
extern char* birth_key_file;
extern char* birth_key_password;
extern char* client_cert_file;
extern char* client_key_file;
extern char* client_key_password;
extern char* key_type;
extern bool  new_device;
extern char* password;
extern bool  reenroll_only;
extern char* subject;
extern char* trust_store;
extern char* username;
extern char* base_ejbca_url;
extern char* est_ee_username;
extern char* est_ee_enrollmentcode_key;
extern char* est_ee_enrollmentcode;
extern char* challenge_password;
extern uint16_t key_size;
extern bool  print_usage_only;
extern bool  est_vendormode;
extern bool  subject_supplied_on_command_line;
extern bool  use_challenge_password;
extern bool  skip_ejbca_check;
extern bool  use_basic_authentication;
#ifdef __ALLOW_NAME_CHANGE__
extern char* alt_subject_name;
extern bool  allow_name_change;
#endif
extern uint16_t ECC_KEY_SIZES[];
extern uint16_t RSA_KEY_SIZES[];

#endif /* __MAIN_H__ */
