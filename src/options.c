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
#define _CRT_SECURE_NO_WARNINGS

#include "../include/options.h"
#include "../include/main.h"
#include "../include/logging.h"
#include <string.h>
#include <stdio.h>
#include <getopt.h>

/******************************************************************************/
/***************************** GLOBAL VARIABLES *******************************/
/******************************************************************************/

/******************************************************************************/
/***************************** LOCAL DEFINES  *********************************/
/******************************************************************************/
#define ALIAS_SWITCH           "alias"
#define BIRTH_CERT_SWITCH      "birthcert"
#define BIRTH_KEY_SWITCH       "birthkey"
#define BIRTH_KEY_PASS_SWITCH  "birthkeypass"
#define CA_CERT_SWITCH         "cacert"
#define CHALLENGE_PASS_SWITCH  "challengepass"
#define CLIENT_CERT_SWITCH     "clientcert"
#define CLIENT_KEY_SWITCH      "clientkey"
#define CLIENT_KEY_PASS_SWITCH "clientpass"
#define LOG_LEVEL_SWITCH       "loglevel"
#define NEW_DEVICE_SWITCH      "newdevice"
#define SKIP_HEALTH_SWITCH     "skiphealth"
#define REENROLL_SWITCH        "reenroll"
#define SUBJECT_SWITCH         "subject"
#define TRUST_SWITCH           "trust"
#define USERNAME_SWITCH        "username" /* for basic auth */
#define PASSWORD_SWITCH        "password" /* for basic auth */
#define URL_SWITCH             "url"
#define EE_KEY_SWITCH          "eekey"
#define EE_USER_SWITCH         "eeuser"
#define EE_PASS_SWITCH         "eepass"
#define KEY_TYPE_SWITCH        "keytype"
#define KEY_SIZE_SWITCH        "keysize"
#define HELP_SWITCH            "help"
#define ALT_SUBJECT_SWITCH     "altsubject"
#define CHANGE_NAME_SWITCH     "allownamechange"
/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL FUNCTION PROTOTYPES ***************************/
/******************************************************************************/

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/* Copy a source string to a destination char*                                */
/* NOTE: This uses dynamic memory and stringToSet must be freed later         */
/*                                                                            */
/* @param  - alias = the name of the alias                                    */
/* @return - true = success                                                   */
/*          false = the destination array isn't large enough to hold source   */
/*                                                                            */
static bool set_string(char** stringToSet, const char* nameToSetString, int maxLen) {
    size_t localMaxLen = maxLen;
    if ( (!nameToSetString) || (localMaxLen < strlen(nameToSetString)) ) {
        fprintf(stderr, "%s::%s(%d) : Error %s is longer than %lu characters or is NULL",
                LOG_INF, nameToSetString, localMaxLen);
        return false;
    } else {
        if ( *stringToSet ) free( *stringToSet );
        *stringToSet = NULL; /* In case of re-entrant code */
        *stringToSet = strdup(nameToSetString);
        if ( !(*stringToSet) ) {
            fprintf(stderr, "%s::%s(%d) : Out of memory", LOG_INF);
            return false;
        }
    }
    return true;
} /* set_string */

/**                                                                           */
/* Convert a string to a unsigned 16 bit number                               */
/*                                                                            */
/* @param  - stringToConvert = a string representing a 16 bit number          */
/* @param  - [output] target = a pointer to a uint16_t variable               */
/* @return - true = success                                                   */
/*          false = the string isn't a number, the string won't fit into a    */
/*                  16 bit unsigned number.                                   */
/*                                                                            */
static bool string_to_uint16_t(const char* stringToConvert, uint16_t* target) {
    static const uint16_t MAX_SIZE = (uint16_t)(2^16);
    uint16_t multiplier = 1;
    unsigned long workingResult = 0;
    int len = strlen(stringToConvert);


    if ( ( 5 < len ) || ( 0 > len ) ) {
        fprintf(stderr,"%s::%s(%d) : Error string %s is to large to convert into a uint16_t",
                LOG_INF, stringToConvert);
        return false;
    }

    for ( int currentPosition = len - 1; 0 <= currentPosition; currentPosition-- ) {
        if ( ('0' <= stringToConvert[currentPosition]) && ('9' >= stringToConvert[currentPosition]) ) {
            workingResult += multiplier * (stringToConvert[currentPosition] - '0');
            multiplier *= 10;
        } else {
            fprintf(stderr,"%s::%s(%d) : Invalid character found in string = %c",
                    LOG_INF, stringToConvert[currentPosition]);
            return false;
        }
    }

    if ( MAX_SIZE < workingResult ) {
        *target = (uint16_t)workingResult;
    } else {
        fprintf(stderr,"%s::%s(%d) : Error string %s is larger than maximum size of %u",
                LOG_INF, stringToConvert, MAX_SIZE);
        return false;
    }

    return true;
} /* string_to_unit16_t */

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/* Print out program command line switches to the stderr                      */
/* @param  - argv[0]                                                          */
/* @return - none                                                             */
/*                                                                            */
void usage(const char *program)
{
    uint16_t major = (uint16_t)((PROGRAM_VERSION) >> (16*3));
    uint16_t minor = (uint16_t)((PROGRAM_VERSION & 0x0000FFFFF00000000) >> (16*2));
    uint16_t build = (uint16_t)((PROGRAM_VERSION & 0x00000000FFFFF0000) >> 16);
    uint16_t revision = (uint16_t)(PROGRAM_VERSION & 0x000000000000FFFF);
    fprintf( stderr,
             "\nKeyfactor reference EST-Lite Client v%hu.%hu.%hu.%hu",
             major, minor, build, revision
    );
    fprintf(stderr, "\n\n"
                    "Usage: %s [-l loglevel]\n\n"
                    "\t-l, --loglevel\tloglevel \tSet the logging level as follows:\n"
                    "\t                         \t  o = turn off logging\n"
                    "\t                         \t  e = error messages only\n"
                    "\t                         \t  i = information and error messages\n"
                    "\t                         \t  w = warning, information, and error messages\n"
                    "\t                         \t  v = verbose, warning, information, and error messages\n"
                    "\t                         \t  d = debug, verbose, warning, information, and error messages\n"
                    "\t                         \t  t = trace, debug, verbose, warning, information, and error messages\n"
            , program
    );
    fprintf(stderr,
            "Examples:\n"
            "\t%s -l t \t Set trace logging level\n"
            "\t%s --help \t print out usage information\n"
            "\t%s -? \t print out usage information\n\n\n"
            , program, program, program
    );
} /* usage */

/**                                                                           */
/*	Check the sanity of the input parameters (after they are all set)         */
/*                                                                            */
/*	@return - true : All parameters make sense                                */
/*			  false: One (or more parameters doesn't make sense)              */
/*                                                                            */
bool validate_parameters(const char* program) {
    bool result = true; /* Assume success until not */

    printf("%s::%s(%d) : Validating input parameters\n", LOG_INF);

    /* Validate EST Vendormode */
    if ( (est_vendormode) && ((!birth_cert_file) || (!birth_key_file)) ) {
        fprintf(stderr,"%s::%s(%d) : Both a birth cert and a birth key must be defined\n", LOG_INF);
        result = false;
    }

    /* Validate Key type and size */
    if ( 0 == strcasecmp("RSA", key_type) ) {
        bool rsaKeyFound = false;
        for (int i = 0; NUM_RSA_KEY_SIZES > i; i++) {
            if ( RSA_KEY_SIZES[i] == key_size ) rsaKeyFound = true;
        }
        if (!rsaKeyFound) {
            fprintf(stderr,"%s::%s(%d) : RSA Key size of %u is not implemented\n", LOG_INF, key_size);
            result = false;
        }
    } else if ( 0 == strcasecmp("ECC", key_type) ) {
        bool eccKeyFound = false;
        for (int i = 0; NUM_ECC_KEY_SIZES > i; i++) {
            if ( ECC_KEY_SIZES[i] == key_size ) eccKeyFound = true;
        }
        if (!eccKeyFound) {
            fprintf(stderr,"%s::%s(%d) : ECC Key size of %u is not implemented\n", LOG_INF, key_size);
            result = false;
        }
    }

#ifdef __KEYFACTOR_TESTING__
    printf("%s::%s(%d) : Did all parameters pass validation? %s\n", LOG_INF, result ? "true" : "false");
#endif

    if (!result) {
        usage(program);
        print_usage_only = true;
    }

    return result;
} /* validate_parameters */

/**                                                                           */
/*	Parse command line switches and set the global variables associated       */
/*	with the switches.                                                        */
/*                                                                            */
/*	@param  - [Input] argc = # of arguments passed                            */
/*	@param  - [Input] const char *argv[] = the array of passed arguments      */
/*	@return - success : true                                                  */
/*			  failure : false                                                 */
/*                                                                            */
bool parse_parameters( int argc, char *argv[] )
{
    struct option longOptions[] = {
            {ALIAS_SWITCH, required_argument, NULL, 0},
            {BIRTH_CERT_SWITCH, required_argument, NULL, 0},
            {CA_CERT_SWITCH, required_argument, NULL, 0},
            {BIRTH_KEY_SWITCH, required_argument, NULL, 0},
            {BIRTH_KEY_PASS_SWITCH, required_argument, NULL, 0},
            {CHALLENGE_PASS_SWITCH, required_argument, NULL, 0},
            {CLIENT_CERT_SWITCH, required_argument, NULL, 0},
            {CLIENT_KEY_SWITCH, required_argument, NULL, 0},
            {CLIENT_KEY_PASS_SWITCH, required_argument, NULL, 0},
            {KEY_TYPE_SWITCH, required_argument, NULL, 0},
            {LOG_LEVEL_SWITCH, required_argument, NULL, 0},
            {NEW_DEVICE_SWITCH, no_argument, NULL, 0},
            {SKIP_HEALTH_SWITCH, no_argument, NULL, 0},
            {PASSWORD_SWITCH, required_argument, NULL, 0},
            {REENROLL_SWITCH, no_argument, NULL, 0},
            {SUBJECT_SWITCH, required_argument, NULL, 0},
            {TRUST_SWITCH, required_argument, NULL, 0},
            {USERNAME_SWITCH, required_argument, NULL, 0},
            {URL_SWITCH, required_argument, NULL, 0},
            {EE_KEY_SWITCH, required_argument, NULL, 0},
            {EE_USER_SWITCH, required_argument, NULL, 0},
            {EE_PASS_SWITCH, required_argument, NULL, 0},
            {KEY_SIZE_SWITCH, required_argument, NULL, 0},
            {HELP_SWITCH, no_argument, NULL, 0},
            {ALT_SUBJECT_SWITCH, required_argument, NULL, 0},
            {CHANGE_NAME_SWITCH, no_argument, NULL, 0},
            {0,0,0,0}
    };
    int optionIndex = 0;

    int opt;

    while (-1 != (opt = getopt_long(argc, argv, "a:b:c:d:f:g:h:i:j:k:l:nop:rs:t:u:v:x:w:y:z:?", longOptions, &optionIndex))) {
        switch (opt) {
            case 0:
                printf("%s::%s(%d) : Option %s was selected", LOG_INF, longOptions[optionIndex].name);
                if (optarg)
                    printf(" with argument %s", optarg);
                printf("\n");
                if (!strncmp(longOptions[optionIndex].name, ALIAS_SWITCH, strlen(ALIAS_SWITCH))) {
                    if (!set_string(&ejbca_est_alias, optarg, MAX_ALIAS_LEN))
                        return false;
                } else if (!strncmp(longOptions[optionIndex].name, BIRTH_CERT_SWITCH,strlen(BIRTH_CERT_SWITCH))) {
                    if ( !set_string(&birth_cert_file, optarg, MAX_BIRTHCERT_NAME) )
                        return false;
                    est_vendormode = true;
                } else if (0 == strncmp(longOptions[optionIndex].name, CA_CERT_SWITCH, strlen(CA_CERT_SWITCH))) {
                    if ( !set_string(&cacert_file, optarg, MAX_CACERTS_NAME) )
                        return false;
                } else if (0 == strncmp(longOptions[optionIndex].name, BIRTH_KEY_SWITCH,strlen(BIRTH_KEY_SWITCH))) {
                    if ( !set_string(&birth_key_file, optarg, MAX_BIRTHKEY_NAME) )
                        return false;
                } else if (0 == strncmp(longOptions[optionIndex].name, BIRTH_KEY_PASS_SWITCH,strlen(BIRTH_KEY_PASS_SWITCH))) {
                    if ( !set_string(&birth_key_password, optarg, MAX_BIRTHKEY_PASS_LEN) )
                        return false;
                } else if (0 == strncmp(longOptions[optionIndex].name, CHALLENGE_PASS_SWITCH,strlen(CHALLENGE_PASS_SWITCH))) {
                    use_challenge_password = true;
                    if ( !set_string(&challenge_password, optarg, MAX_PASSWORD_LEN) )
                        return false;
                } else if (0 == strncmp(longOptions[optionIndex].name, CLIENT_CERT_SWITCH,strlen(CLIENT_CERT_SWITCH))) {
                    if ( !set_string(&client_cert_file, optarg, MAX_CLIENTCERT_NAME) )
                        return false;
                } else if (0 == strncmp(longOptions[optionIndex].name, CLIENT_KEY_SWITCH,strlen(CLIENT_KEY_SWITCH))) {
                    if ( !set_string(&client_key_file, optarg, MAX_CLIENTKEY_NAME) )
                        return false;
                } else if (0 == strncmp(longOptions[optionIndex].name, CLIENT_KEY_PASS_SWITCH,strlen(CLIENT_KEY_PASS_SWITCH))) {
                    if ( !set_string(&client_key_password, optarg, MAX_CLIENTPASS_NAME) )
                        return false;
                } else if (0 == strncmp(longOptions[optionIndex].name, KEY_TYPE_SWITCH,strlen(KEY_TYPE_SWITCH))) {
                    if ( !set_string(&key_type, optarg, MAX_KEY_TYPEVAR) )
                        return false;
                } else if (0 == strncmp(longOptions[optionIndex].name, LOG_LEVEL_SWITCH,strlen(LOG_LEVEL_SWITCH))) {
                    printf("%s::%s(%d) : Setting logging level to ", LOG_INF);
                    switch (optarg[0]) {
                        case 'v':
                            printf("verbose\n");
                            log_set_verbosity(true);
                            break;
                        case 'i':
                            printf("info\n");
                            log_set_info(true);
                            break;
                        case 'e':
                            printf("error\n");
                            log_set_error(true);
                            break;
                        case 'o':
                            printf("TURNING OFF LOGGING\n");
                            log_set_off(true);
                            break;
                        case 'd':
                            printf("debug\n");
                            log_set_debug(true);
                            break;
                        case 't':
                            printf("trace\n");
                            log_set_trace(true);
                            break;
                        case 'w':
                            printf("warning\n");
                            log_set_warn(true);
                            break;
                        case '?':
                            printf("Unknown logging level - setting log level to info\n");
                            log_set_info(true);
                            break;
                        default:
                            printf("Default level = info\n");
                            log_set_info(true);
                            break;
                    }
                } else if (0 == strncmp(longOptions[optionIndex].name, NEW_DEVICE_SWITCH,strlen(NEW_DEVICE_SWITCH))) {
                    if ( reenroll_only ) {
                        printf("%s::%s(%d) : The %s and %s switches are incompatible\n",
                               LOG_INF, NEW_DEVICE_SWITCH, REENROLL_SWITCH);
                        usage(argv[0]);
                        print_usage_only = true;
                        return false;
                    } else {
                        new_device = true;
                    }
                } else if (0 == strncmp(longOptions[optionIndex].name, SKIP_HEALTH_SWITCH,strlen(SKIP_HEALTH_SWITCH))) {
                    skip_ejbca_check = true;
                } else if (0 == strncmp(longOptions[optionIndex].name, PASSWORD_SWITCH,strlen(PASSWORD_SWITCH))) {
                    use_basic_authentication = true;
                    if ( !set_string(&password, optarg, MAX_PASSWORD_LEN) )
                        return false;
                } else if (0 == strncmp(longOptions[optionIndex].name, REENROLL_SWITCH,strlen(REENROLL_SWITCH))) {
                    if ( new_device ) {
                        printf("%s::%s(%d) : The %s and %s switches are incompatible\n",
                               LOG_INF, NEW_DEVICE_SWITCH, REENROLL_SWITCH);
                        usage(argv[0]);
                        print_usage_only = true;
                        return false;
                    } else {
                        reenroll_only = true;
                    }
                } else if (0 == strncmp(longOptions[optionIndex].name, SUBJECT_SWITCH,strlen(SUBJECT_SWITCH))) {
                    subject_supplied_on_command_line = true;
                    if ( !set_string(&subject, optarg, MAX_SUBJECT_LEN) )
                        return false;
                } else if (0 == strncmp(longOptions[optionIndex].name, TRUST_SWITCH,strlen(TRUST_SWITCH))) {
                    if ( !set_string(&trust_store, optarg, MAX_TRUST_STORE_NAME) )
                        return false;
                } else if (0 == strncmp(longOptions[optionIndex].name, USERNAME_SWITCH,strlen(USERNAME_SWITCH))) {
                    use_basic_authentication = true;
                    if ( !set_string(&username, optarg, MAX_USERNAME_LEN) )
                        return false;
                } else if (0 == strncmp(longOptions[optionIndex].name, URL_SWITCH,strlen(URL_SWITCH))) {
                    if ( !set_string(&base_ejbca_url, optarg, MAX_BASE_URL_LEN) )
                        return false;
                } else if (0 == strncmp(longOptions[optionIndex].name, EE_KEY_SWITCH,strlen(EE_KEY_SWITCH))) {
                    if ( !set_string(&est_ee_enrollmentcode_key, optarg, MAX_ENROLLMENT_KEY_LEN) )
                        return false;
                } else if (0 == strncmp(longOptions[optionIndex].name, EE_USER_SWITCH,strlen(EE_USER_SWITCH))) {
                    if ( !set_string(&est_ee_username, optarg, MAX_ENROLLMENT_USER_LN) )
                        return false;
                } else if (0 == strncmp(longOptions[optionIndex].name, EE_PASS_SWITCH,strlen(EE_PASS_SWITCH))) {
                    if ( !set_string(&est_ee_enrollmentcode, optarg, MAX_ENROLLMENT_CODE_LEN) )
                        return false;
                } else if (0 == strncmp(longOptions[optionIndex].name, KEY_SIZE_SWITCH,strlen(KEY_SIZE_SWITCH))) {
                    char* keysizeString = NULL;
                    if ( !set_string(&keysizeString, optarg, MAX_KEYSIZE_LEN)) {
                        fprintf(stderr,"%s::%s(%d) : Error copying keysize, exiting\n", LOG_INF);
                        return false;
                    }
                    if ( !string_to_uint16_t(keysizeString, &key_size) ) {
                        fprintf(stderr, "%s::%s(%d) : Error converting %s to uint16_t\n",
                                LOG_INF, keysizeString);
                        return false;
                    }
                    printf("%s::%s(%d) : Key size set to %u\n", LOG_INF, key_size);
                } else if (0 == strncmp(longOptions[optionIndex].name, HELP_SWITCH,strlen(HELP_SWITCH))) {
                    usage(argv[0]);
                    print_usage_only = true;
                } else if (0 == strncmp(longOptions[optionIndex].name, ALT_SUBJECT_SWITCH,strlen(ALT_SUBJECT_SWITCH))) {
#if __ALLOW_NAME_CHANGE__
                    if ( !set_string(&alt_subject_name, optarg, MAX_SUBJECT_LEN) )
                        return false;
#else
                    fprintf(stderr, "%s::%s(%d) : Error allow name change is not implemented in this compiled version -- ignoring", LOG_INF);
#endif
                } else if (0 == strncmp(longOptions[optionIndex].name, CHANGE_NAME_SWITCH,strlen(CHANGE_NAME_SWITCH))) {
#if __ALLOW_NAME_CHANGE__
                    allow_name_change = true;
#else
                    fprintf(stderr, "%s::%s(%d) : Error allow name change is not implemented in this compiled version -- ignoring", LOG_INF);
#endif
                } else {
                    printf("%s::%s(%d) Unknown switch option\n", LOG_INF);
                    usage(argv[0]);
                    print_usage_only = true;
                    return false;
                }
                break;
            default:
                printf("%s::%s(%d) Dropped into the default option\n", LOG_INF);
                usage(argv[0]);
                print_usage_only = true;
                return false;
                break;
        } /* switch */
    } /* while */

    return true;
} /* parse_parameters */
