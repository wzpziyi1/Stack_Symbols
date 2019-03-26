//
//  StackAddress.hpp
//  MachO_Test
//
//  Created by wzp on 2019/3/25.
//  Copyright © 2019 wzp. All rights reserved.
//

#ifndef StackAddress_hpp
#define StackAddress_hpp

#include <stdio.h>
#include <iostream>
#include <mach/vm_types.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <vector>
#import <mach/mach.h>
#import <malloc/malloc.h>
#import <mach/vm_types.h>
#import "execinfo.h"
#import <CommonCrypto/CommonDigest.h>
using namespace std;

#if defined(__i386__)

#define MY_THREAD_STATE_COUTE x86_THREAD_STATE32_COUNT
#define MY_THREAD_STATE x86_THREAD_STATE32
#define MY_EXCEPTION_STATE_COUNT x86_EXCEPTION_STATE64_COUNT
#define MY_EXCEPITON_STATE ARM_EXCEPTION_STATE32
#define MY_SEGMENT_CMD_TYPE LC_SEGMENT

#elif defined(__x86_64__)

#define MY_THREAD_STATE_COUTE x86_THREAD_STATE64_COUNT
#define MY_THREAD_STATE x86_THREAD_STATE64
#define MY_EXCEPTION_STATE_COUNT x86_EXCEPTION_STATE64_COUNT
#define MY_EXCEPITON_STATE x86_EXCEPTION_STATE64
#define MY_SEGMENT_CMD_TYPE LC_SEGMENT_64

#elif defined(__arm64__)

#define MY_THREAD_STATE_COUTE ARM_THREAD_STATE64_COUNT
#define MY_THREAD_STATE ARM_THREAD_STATE64
#define MY_EXCEPTION_STATE_COUNT ARM_EXCEPTION_STATE64_COUNT
#define MY_EXCEPITON_STATE ARM_EXCEPTION_STATE64
#define MY_SEGMENT_CMD_TYPE LC_SEGMENT_64

#elif defined(__arm__)

#define MY_THREAD_STATE_COUTE ARM_THREAD_STATE_COUNT
#define MY_THREAD_STATE ARM_THREAD_STATE
#define MY_EXCEPITON_STATE ARM_EXCEPTION_STATE
#define MY_EXCEPTION_STATE_COUNT ARM_EXCEPTION_STATE_COUNT
#define MY_SEGMENT_CMD_TYPE LC_SEGMENT

#else
#error Unsupported host cpu.
#endif


#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
#endif

typedef struct {
    const char *name;
    long loadAddr;
    long startAddr;
    long endAddr;
}segImageInfo;

typedef struct {
    size_t size;
    segImageInfo **imageInfos;
}AppImages;

class StackAddress {
    AppImages allImages;
    
public:
    StackAddress();
    ~StackAddress();
    bool getImageByAddress(vm_address_t address, segImageInfo *info);
};

#endif /* StackAddress_hpp */
