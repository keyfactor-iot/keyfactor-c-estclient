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

#include "../include/logging.h"
#include "../include/file_utilities.h"

#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

/******************************************************************************/
/***************************** GLOBAL VARIABLES *******************************/
/******************************************************************************/

/******************************************************************************/
/***************************** LOCAL DEFINES  *********************************/
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
/**                                                                           */
/*   Copy a file's contents without using the underlying OS                   */
/*                                                                            */
/*   @param srcPath = the filename to copy                                    */
/*   @param destPath = the filename to populate                               */
/*   @retval 0 = file backed up successfully                                  */
/*   @retval other integer = error code from files or such                    */
/*                                                                            */
static int copy_file(const char* srcPath, const char* destPath) {
    int err = 0;
    FILE* fpWrite = NULL;
    FILE* fpRead = NULL;

    struct stat st;
    if(0 != stat(srcPath, &st))	{
		err = errno;
		goto exit;
	}
    fpRead = fopen(srcPath, "rb");
    if(!fpRead) {
		err = errno;
		goto exit;
	}
    fpWrite = fopen(destPath, "wb");
    if(!fpWrite) {
		err = errno;
		goto exit;
	}

    char buf[1024];
	size_t rcnt;
	while (0 < (rcnt = fread(buf, 1, 1024, fpRead))) {
		if (rcnt != (fwrite(buf, 1, rcnt, fpWrite))) {
			err = ferror(fpWrite);
			goto exit;
		}
	}

exit:
	if (fpRead) fclose(fpRead);
    if (fpWrite) fclose(fpWrite);
    return err;
} /* copy_file */


/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/
/**                                                                           */
/*   Check if a file exists and the program can read it                       */
/*                                                                            */
/*   @param fileName = the filename to look on the filesystem for             */
/*   @retval true = file exists                                               */
/*   @retval false = file isn't there or other error                          */
/*                                                                            */
bool file_exists( const char *fileName ) {
    FILE *fp;
    if ( (fp = fopen( fileName, "r")) ) {
        (void)fclose(fp);
        return true;
    } else {
        return false;
    }
} /* file_exists */

/**                                                                           */
/*   Backup a file with an appended ~                                         */
/*                                                                            */
/*   @param file = the filename to backup                                     */
/*   @retval 0 = file backed up successfully                                  */
/*   @retval other integer = error code from files or such                    */
/*                                                                            */
int backup_file(const char* file) {
    int err = 0;
    char* dummy = NULL;

    if(file) {
        if ( !file_exists( file ) )
            create_file( file );

        char backupPath[strlen(file) + 2];
        strcpy(backupPath, file);
        strcat(backupPath, "~");
        err = copy_file(file, backupPath);

        if(!err) {
            if(chmod(backupPath, (S_IRUSR | S_IWUSR )) < 0)
                err = errno;
        }
    } else {
        log_info("%s::%s(%d) : No file name passed to backup_file function", LOG_INF);
        free(dummy);
        err = ENOENT;
    }

    return err;
} /* backup_file */

/**                                                                           */
/*   Overwrite a file or create a new file filled with data                   */
/*                                                                            */
/*   @param file = the filename to populate                                   */
/*   @param contents = the contents to place into the file                    */
/*   @param len = the length of the content to populate                       */
/*   @param backup = true = make a backup of a file first, false = overwrite  */
/*   @retval 0 = everything was successful                                    */
/*   @retval other integer = error code from files or such                    */
/*                                                                            */
int replace_file(const char* file, const char* contents, long len, bool backup)
{
    int err = 0;

    if (backup) err = backup_file(file);

    if(!err || err == ENOENT) {
        err = 0; /* Inability to backup a file because it doesn't exist is fine */

        FILE* fpWrite = fopen(file, "w");
        if(!fpWrite) {
            err = errno;
            char* errStr = strerror(errno);
            log_error("%s::%s(%d) : Unable to open file %s for writing: %s", LOG_INF, file, errStr);
        } else {
            log_verbose("%s::%s(%d) : Preparing to write %ld bytes to the file %s", LOG_INF, len, file);

            if(fwrite(contents, 1, len, fpWrite) == (size_t)len) {
                log_verbose("%s::%s(%d) : File %s written successfully", LOG_INF, file);
            } else {
                err = errno;
                char* errStr = strerror(errno);
                log_error("%s::%s(%d) : Unable to write file at %s: %s", LOG_INF, file, errStr);
            }
        }

        if(fpWrite) fclose(fpWrite);
    }
    return err;
} /* replace_file */

/**                                                                           */
/*   Read a file into a buffer                                                */
/*   The file can be binary or text                                           */
/*                                                                            */
/* NOTE: This function allocates dynamic memory & that memory must be freed   */
/*       by the calling program to prevent any memory leaks.                  */
/*                                                                            */
/*   @param srcPath = the filename to read                                    */
/*   @param pFileByptes = Pointer to the string/binary variable to populate   */
/*   @param fileLen = the length of the content read                          */
/*   @retval 0 = everything was successful                                    */
/*   @retval other integer = error code from files or such                    */
/*                                                                            */
int read_file_bytes(const char* srcPath, unsigned char** pFileBytes, size_t* fileLen) {

    int err = 0;
    FILE* fpRead = fopen(srcPath, "r");

    if(!fpRead)	{
        err = errno;
    } else if (fseek(fpRead, 0, SEEK_END) != 0) {
        err = ferror(fpRead);
    } else {
		errno = 0;
        int temp = ftell(fpRead);
		if (0 != errno) {
			err = errno;
			goto exit;
		}
        if (0 > temp) {
            *fileLen = 0;
		} else {
            *fileLen = (size_t)temp;
		}
        *pFileBytes = (unsigned char*)calloc((*fileLen) + 1, 1);
        if (!(*pFileBytes)) {
            log_error("%s::%s(%d) : Out of memory", LOG_INF);
            goto exit;
        }

        fseek(fpRead, 0, SEEK_SET);

        int rcnt = fread(*pFileBytes, 1, *fileLen, fpRead);
        if( (size_t)rcnt != *fileLen ) {
            err = ferror(fpRead);
            free(*pFileBytes);
            *fileLen = 0;
        }
    }

    exit:
    if(fpRead) fclose(fpRead);
    return err;
}

/**                                                                           */
/*	Creates a blank file                                                      */
/*                                                                            */
/*	@param const char *file = path and filename of file to create             */
/*	@returns false if creation fails                                          */
/*           true if the file is created                                      */
/*                                                                            */
bool create_file( const char *file ) {
    bool retval = false;
    FILE *fd;
    fd = fopen( file, "w" );
    if ( fd ) {
        fclose( fd );
        retval = true;
    }
    return retval;
} /* create_file */
/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/