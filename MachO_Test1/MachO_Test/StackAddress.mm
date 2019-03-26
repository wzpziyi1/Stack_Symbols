//
//  StackAddress.m
//  MachO_Test
//
//  Created by wzp on 2019/3/25.
//  Copyright © 2019 wzp. All rights reserved.
//

#import "StackAddress.h"

StackAddress::StackAddress() {
    //获得加载的动态库的数量
    uint32_t count = _dyld_image_count();
    allImages.imageInfos = (segImageInfo **)malloc(sizeof(segImageInfo *) * count);
    allImages.size = 0;
    
    for (uint32_t i = 0; i < count; i++) {
        //每个image都是一个macho文件，取出头部地址
        const mach_header_t *header = (const mach_header_t *)_dyld_get_image_header(i);
        const char *name = _dyld_get_image_name(i);
        long slide = _dyld_get_image_vmaddr_slide(i);
        const char* tmp = strrchr(name, '/');
        if (tmp) {
            name = tmp + 1;
        }
        //load commands的起始地址
        long offset = (long)header + sizeof(mach_header_t);
        //macho的head里面有关于它的load commands的数量
        for (int i = 0; i < header->ncmds; i++) {
            const segment_command_t *segment = (segment_command_t *)offset;
            /* segment_type
             LC_SEGMENT_64            将文件中（32位或64位）的段映射到进程地址空间中。
             LC_SYMTAB                符号表地址。
             LC_DYSYMTAB                动态符号表地址
             LC_DYLD_INFO_ONLY        动态链接相关信息
             LC_LOAD_DYLINKER        加载一个动态链接器（动态库加载器），通常路径是“/usr/lib/dyld”。
             LC_LOAD_DYLIB:            加载一个动态链接共享库。如“/usr/lib/libSystem.B.dylib”，这是C标准库。每个                            库由动态链接器加载并包含一个符号表。
             
             LC_UUID                    文件的唯一标识，crash解析中也会有该值，去确定dysm文件和crash文件是匹配的。
             LC_VERSION_MIN_MACOSX    二进制文件要求的最低操作系统版本
             LC_MAIN                    设置程序主线程的入口地址和栈大小
             LC_SOURCE_VERSION        构建该二进制文件使用的源代码版本
             LC_FUNCTION_STARTS        定义一个函数起始地址表，使调试器和其他程序易于看到一个地址是否在函数内
             LC_DATA_IN_CODE            定义在代码段内的非指令数据
             */
            
            //所在segment是代码段
            if (segment->cmd == MY_SEGMENT_CMD_TYPE && strcmp(segment->segname, SEG_TEXT) == 0) {
                long startAddr = (long)(segment->vmaddr) + slide;
                long endAddr = (long)(segment->vmsize) + startAddr;
                segImageInfo *info = (segImageInfo *)malloc(sizeof(segImageInfo));
                info->loadAddr = (long)header;
                info->startAddr = startAddr;
                info->endAddr = endAddr;
                info->name = name;
                allImages.imageInfos[allImages.size++] = info;
                break;
            }
            offset += segment->cmdsize;
        }
    }
}

StackAddress::~StackAddress()
{
    for (size_t i = 0; i < allImages.size; i++)
    {
        free(allImages.imageInfos[i]);
    }
    free(allImages.imageInfos);
    allImages.imageInfos = NULL;
    allImages.size = 0;
}

bool StackAddress::getImageByAddress(vm_address_t addr,segImageInfo *image){
    for (size_t i = 0; i < allImages.size; i++)
    {
        if (addr > allImages.imageInfos[i]->startAddr && addr < allImages.imageInfos[i]->endAddr) {
            image->name = allImages.imageInfos[i]->name;
            image->loadAddr = allImages.imageInfos[i]->loadAddr;
            image->startAddr = allImages.imageInfos[i]->startAddr;
            image->endAddr = allImages.imageInfos[i]->endAddr;
            return true;
        }
    }
    return false;
}

