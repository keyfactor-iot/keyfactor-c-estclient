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

#include "../include/options.h"
#include "../include/main.h"
#include "../include/logging.h"
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <ctype.h>

/******************************************************************************/
/***************************** GLOBAL VARIABLES *******************************/
/******************************************************************************/

/******************************************************************************/
/***************************** LOCAL DEFINES  *********************************/
/******************************************************************************/
/* NOTE: These must all be lower case!!! */

#define ALIAS_SWITCH           "alias"			/* _HASH	210706582927 */
#define BIRTH_CERT_SWITCH      "birthcert"		/* _HASH	249882652442070764 */
#define BIRTH_KEY_SWITCH       "birthkey"		/* _HASH	7572201589162375 */
#define BIRTH_KEY_PASS_SWITCH  "birthkeypass"	/* _HASH	14915260998194971486 */
#define CA_CERT_SWITCH         "cacert"			/* _HASH	6953382251063 */
#define CHALLENGE_PASS_SWITCH  "challengepass"	/* _HASH	14179211678630328095 */
#define CLIENT_CERT_SWITCH     "clientcert"		/* _HASH	8246177758615472594 */
#define CLIENT_KEY_SWITCH      "clientkey"		/* _HASH	249884174503507885 */
#define CLIENT_KEY_PASS_SWITCH "clientpass"		/* _HASH	8246177758615935451 */
#define LOG_LEVEL_SWITCH       "loglevel"		/* _HASH	7572635082327423 */
#define NEW_DEVICE_SWITCH      "newdevice"		/* _HASH	249899364700020191 */
#define SKIP_HEALTH_SWITCH     "skiphealth"		/* _HASH	8246918949910767890 */
#define REENROLL_SWITCH        "reenroll"		/* _HASH	7572877802866440 */
#define SUBJECT_SWITCH         "subject"		/* _HASH	229483059459605 */
#define TRUST_SWITCH           "trust"			/* _HASH	210729344711 */
#define USERNAME_SWITCH        "username"		/* _HASH	7573023743331653 */
#define PASSWORD_SWITCH        "password"		/* _HASH	7572787954113592 */
#define URL_SWITCH             "url"			/* _HASH	193508280 */
#define EE_KEY_SWITCH          "eekey"			/* _HASH	210711077368 */
#define EE_USER_SWITCH         "eeuser"			/* _HASH	6953465927214 */
#define EE_PASS_SWITCH         "eepass"			/* _HASH	6953465728390 */
#define KEY_TYPE_SWITCH        "keytype"		/* _HASH	229472129207312 */
#define KEY_SIZE_SWITCH        "keysize"		/* _HASH	229472129154281 */
#define HELP_SWITCH            "help"			/* _HASH	6385292014 */
#define ALT_SUBJECT_SWITCH     "altsubject"		/* _HASH	8246085422782945238 */
#define CHANGE_NAME_SWITCH     "allownamechange"/* _HASH	1451348330401914795 */

#define ALIAS_SWITCH_HASH			210706582927UL
#define BIRTH_CERT_SWITCH_HASH		249882652442070764UL
#define BIRTH_KEY_SWITCH_HASH		7572201589162375UL
#define BIRTH_KEY_PASS_SWITCH_HASH	14915260998194971486UL
#define CA_CERT_SWITCH_HASH			6953382251063UL
#define CHALLENGE_PASS_SWITCH_HASH	14179211678630328095UL
#define CLIENT_CERT_SWITCH_HASH		8246177758615472594UL
#define CLIENT_KEY_SWITCH_HASH		249884174503507885UL
#define CLIENT_KEY_PASS_SWITCH_HASH	8246177758615935451UL
#define LOG_LEVEL_SWITCH_HASH		7572635082327423UL
#define NEW_DEVICE_SWITCH_HASH		249899364700020191UL
#define SKIP_HEALTH_SWITCH_HASH		8246918949910767890UL
#define REENROLL_SWITCH_HASH		7572877802866440UL
#define SUBJECT_SWITCH_HASH			229483059459605UL
#define TRUST_SWITCH_HASH			210729344711UL
#define USERNAME_SWITCH_HASH		7573023743331653UL
#define PASSWORD_SWITCH_HASH		7572787954113592UL
#define URL_SWITCH_HASH				193508280UL
#define EE_KEY_SWITCH_HASH			210711077368UL
#define EE_USER_SWITCH_HASH			6953465927214UL
#define EE_PASS_SWITCH_HASH			6953465728390UL
#define KEY_TYPE_SWITCH_HASH		229472129207312UL
#define KEY_SIZE_SWITCH_HASH		229472129154281UL
#define HELP_SWITCH_HASH			6385292014UL
#define ALT_SUBJECT_SWITCH_HASH		8246085422782945238UL
#define CHANGE_NAME_SWITCH_HASH		1451348330401914795UL

static const unsigned int MAX_COMMAND_LENGTH = 64;

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/
static const struct option longOptions[] = {
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
/* Change a string to all lower case                                          */
/* This is meant to be used with a char array with a fixed length.            */
/*                                                                            */
/* @param [Input/Output] - str = the string to convert to lower case          */
/* @param [Input] - The maximum length to process to prevent memory errors    */
/*                                                                            */
static void to_lowercase(char* str, unsigned int maxLen) {
	if (str == NULL) { /* parasoft-suppress MISRAC2012-DIR_4_1-f "Parasoft false positive */
		return;
	}
    unsigned int i = 0;
	while ( (i < maxLen) && (str[i] != '\0') ) {
		str[i] = tolower((unsigned char) str[i]);
		i++;
	}
    return;
}

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
/* Rewrite accepted key type aliases to their canonical form.                 */
/*                                                                            */
/* ECDSA and EC are accepted spellings of ECC. Canonicalizing once, here at   */
/* parse time, means every downstream comparison only has to know the         */
/* canonical names. Matching the aliases at each comparison site instead      */
/* invites the sites to drift apart: an alias added to the dispatch in csr.c  */
/* but not to the key-size validation below silently skips validation, and    */
/* the ECC generator's unknown-size path then decides what to do with an      */
/* unvalidated size.                                                          */
/*                                                                            */
/* @param  - [Input/Output] : keyTypeToCanonicalize rewritten in place        */
/* @return - success : true                                                   */
/*         - failure : false (out of memory)                                  */
/*                                                                            */
static bool canonicalize_key_type(char** keyTypeToCanonicalize) {
    if ( (!keyTypeToCanonicalize) || (!(*keyTypeToCanonicalize)) ) return true;

    if ( (0 == strcasecmp(*keyTypeToCanonicalize, "ECDSA")) ||
         (0 == strcasecmp(*keyTypeToCanonicalize, "EC")) ) {
        free( *keyTypeToCanonicalize );
        *keyTypeToCanonicalize = strdup("ECC");
        if ( !(*keyTypeToCanonicalize) ) {
            fprintf(stderr, "%s::%s(%d) : Out of memory", LOG_INF);
            return false;
        }
    }
    return true;
} /* canonicalize_key_type */

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
    static const uint16_t MAX_SIZE = (uint16_t)(1 << 16);
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

/**                                                                           */
/*	Create a quick and simple hash of a string.  The algorithm was created    */
/*  by Professor Daniel J. Bernstein, and shouldn't be used cryptographically */
/*                                                                            */
/*	@return - The DJB2 Hash of the string as an unsigned long integer         */
/*                                                                            */
static unsigned long djb2_hash(const char* str) {
    unsigned long hash = 5381; /* Seed needs to be prime & 'big' */
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

/**                                                                           */
/*	Set the logging level                                                     */
/*                                                                            */
/*	@return - n/a                                                             */
/*                                                                            */
static void set_logging_level(char level) {
    printf("%s::%s(%d) : Setting logging level to ", LOG_INF);
    switch (level) {
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
    return;
}

/**                                                                           */
/*	Process the key size switch function                                      */
/*                                                                            */
/*	@return - true : The key size was set correctly                           */
/*			  false: We couldn't process the key size                         */
/*                                                                            */
static bool set_key_size(char* size) {
    bool result = true;
    char* keySizeString = NULL;
    if ( !set_string(&keySizeString, size, MAX_KEYSIZE_LEN)) {
        fprintf(stderr,"%s::%s(%d) : Error copying key size, exiting\n", LOG_INF);
        result = false;
    } else if ( !string_to_uint16_t(keySizeString, &key_size) ) {
        fprintf(stderr, "%s::%s(%d) : Error converting %s to uint16_t\n", LOG_INF, keySizeString);
        result = false;
    } else {
        printf("%s::%s(%d) : Key size set to %u\n", LOG_INF, key_size);
    }
    return result;
} /* set_key_size */

/**                                                                           */
/*	Process the re-enroll device switch option                                */
/*                                                                            */
/*  @param [Input] : The name of the program called on the command line       */
/*	@return - true : The re-enroll only flag is set                           */
/*			  false: The new-device switch is set creating a conflict         */
/*                                                                            */
static bool do_re_enroll_switch(char* programName) {
    bool result = true;
    if ( new_device ) {
        printf("%s::%s(%d) : The %s and %s switches are incompatible\n",
               LOG_INF, NEW_DEVICE_SWITCH, REENROLL_SWITCH);
        usage(programName);
        print_usage_only = true;
        result = false;
    } else {
        reenroll_only = true;
    }
    return result;
}

/**                                                                           */
/*	Process the new device switch option                                      */
/*                                                                            */
/*  @param [Input] : The name of the program called on the command line       */
/*	@return - true : The new_device flag is set                               */
/*			  false: The re-enroll only switch was set creating a conflict    */
/*                                                                            */
static bool do_new_device_switch(char* programName) {
    bool result = true;
    if ( reenroll_only ) {
        printf("%s::%s(%d) : The %s and %s switches are incompatible\n", LOG_INF,
               NEW_DEVICE_SWITCH, REENROLL_SWITCH);
        usage(programName);
        print_usage_only = true;
        result = false;
    } else {
        new_device = true;
    }
    return result;
} /* do_new_device_switch */

/**                                                                           */
/*	Parse a single command line switch and set the global variables needed    */
/*                                                                            */
/*	@param  - [Input] The command line switch (in text) that was passed       */
/*	@param  - [Input] const char *argv[] = the array of passed arguments      */
/*	@return - success : true                                                  */
/*			  failure : false                                                 */
/*                                                                            */
static bool parse_single_option( int optionIndex, char *argv[] ) {

    bool result = true;

    printf("%s::%s(%d) : Option %s was selected", LOG_INF, longOptions[optionIndex].name);
    if (optarg)
        printf(" with argument %s", optarg);
    printf("\n");

    char lowercase_option[MAX_COMMAND_LENGTH];
    snprintf(lowercase_option,(size_t)MAX_COMMAND_LENGTH,"%s", longOptions[optionIndex].name);
    to_lowercase(lowercase_option, MAX_COMMAND_LENGTH);

    /* Perform a quick hash of the lower-case string to map it to an unsigned long integer */
    unsigned long hash = djb2_hash(lowercase_option);

    /* Process the switch */
    switch (hash) {
        case ALIAS_SWITCH_HASH:
            result = set_string(&ejbca_est_alias, optarg, MAX_ALIAS_LEN);
            break;
        case BIRTH_CERT_SWITCH_HASH:
            est_vendormode = true;
            result = set_string(&birth_cert_file, optarg, MAX_BIRTHCERT_NAME);
            break;
        case CA_CERT_SWITCH_HASH:
            result = set_string(&cacert_file, optarg, MAX_CACERTS_NAME);
            break;
        case BIRTH_KEY_SWITCH_HASH:
            result = set_string(&birth_key_file, optarg, MAX_BIRTHKEY_NAME);
            break;
        case BIRTH_KEY_PASS_SWITCH_HASH:
            result = set_string(&birth_key_password, optarg, MAX_BIRTHKEY_PASS_LEN);
            break;
        case CHALLENGE_PASS_SWITCH_HASH:
            use_challenge_password = true;
            result = set_string(&challenge_password, optarg, MAX_PASSWORD_LEN);
            break;
        case CLIENT_CERT_SWITCH_HASH:
            result = set_string(&client_cert_file, optarg, MAX_CLIENTCERT_NAME);
            break;
        case CLIENT_KEY_SWITCH_HASH:
            result = set_string(&client_key_file, optarg, MAX_CLIENTKEY_NAME);
            break;
        case CLIENT_KEY_PASS_SWITCH_HASH:
            result = set_string(&client_key_password, optarg, MAX_CLIENTPASS_NAME);
            break;
        case KEY_TYPE_SWITCH_HASH:
            result = set_string(&key_type, optarg, MAX_KEY_TYPEVAR);
            if ( result ) result = canonicalize_key_type(&key_type);
            break;
        case LOG_LEVEL_SWITCH_HASH:
            set_logging_level(optarg[0]);
            break;
        case NEW_DEVICE_SWITCH_HASH:
            result = do_new_device_switch(argv[0]);
            break;
        case SKIP_HEALTH_SWITCH_HASH:
            skip_ejbca_check = true;
            break;
        case REENROLL_SWITCH_HASH:
            result = do_re_enroll_switch(argv[0]);
            break;
        case PASSWORD_SWITCH_HASH:
            use_basic_authentication = true;
            result = set_string(&password, optarg, MAX_PASSWORD_LEN);
            break;
        case SUBJECT_SWITCH_HASH:
            subject_supplied_on_command_line = true;
            result = set_string(&subject, optarg, MAX_SUBJECT_LEN);
            break;
        case TRUST_SWITCH_HASH:
            result = set_string(&trust_store, optarg, MAX_TRUST_STORE_NAME);
            break;
        case USERNAME_SWITCH_HASH:
            use_basic_authentication = true;
            result = set_string(&username, optarg, MAX_USERNAME_LEN);
            break;
        case URL_SWITCH_HASH:
            result = set_string(&base_ejbca_url, optarg, MAX_BASE_URL_LEN);
            break;
        case EE_KEY_SWITCH_HASH:
            result = set_string(&est_ee_enrollmentcode_key, optarg, MAX_ENROLLMENT_KEY_LEN);
            break;
        case EE_USER_SWITCH_HASH:
            result = set_string(&est_ee_username, optarg, MAX_ENROLLMENT_USER_LN);
            break;
        case EE_PASS_SWITCH_HASH:
            result = set_string(&est_ee_enrollmentcode, optarg, MAX_ENROLLMENT_CODE_LEN);
            break;
        case KEY_SIZE_SWITCH_HASH:
            result = set_key_size(optarg);
            break;
        case HELP_SWITCH_HASH:
            usage(argv[0]);
            print_usage_only = true;
            break;
        case ALT_SUBJECT_SWITCH_HASH:
#if __ALLOW_NAME_CHANGE__
            result = set_string(&alt_subject_name, optarg, MAX_SUBJECT_LEN);
#else
            fprintf(stderr, "%s::%s(%d) : Error allow name change is not implemented in this compiled version -- ignoring", LOG_INF);
#endif
            break;
        case CHANGE_NAME_SWITCH_HASH:
#if __ALLOW_NAME_CHANGE__
            allow_name_change = true;
#else
            fprintf(stderr, "%s::%s(%d) : Error allow name change is not implemented in this compiled version -- ignoring", LOG_INF);
#endif
            break;
        default:
            printf("%s::%s(%d) Unknown switch option\n", LOG_INF);
            usage(argv[0]);
            print_usage_only = true;
            result = false;
            break;
    } /* switch */

    return result;
} /* parse_single_option */

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

    int optionIndex = 0;
    int opt;

    while (-1 != (opt = getopt_long(argc, argv, "a:b:c:d:f:g:h:i:j:k:l:nop:rs:t:u:v:x:w:y:z:?", longOptions, &optionIndex))) {
        switch (opt) {
            case 0:
                if (!parse_single_option(optionIndex, argv)) {
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
