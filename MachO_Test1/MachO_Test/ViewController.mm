//
//  ViewController.m
//  MachO_Test
//
//  Created by wzp on 2019/3/25.
//  Copyright © 2019 wzp. All rights reserved.
//

#import "ViewController.h"
#import "StackAddress.h"

@interface ViewController ()

@end
StackAddress *_stackHelper = NULL;
@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    if (_stackHelper == NULL) {
        _stackHelper = new StackAddress();
    }
    int maxCount = 50;
    vm_address_t *stack[maxCount];
    int count = backtrace((void **)stack, maxCount);
//    backtrace_symbols(void *const *, <#int#>)
    for (size_t i = 0; i < count; i++) {
        vm_address_t vmAddr = (vm_address_t)stack[i];
        segImageInfo info;
        if (_stackHelper->getImageByAddress(vmAddr, &info)) {
            NSLog(@"\"%lu %s 0x%lx 0x%lx\" ", i, (info.name == NULL) ? "unknow" : info.name, info.loadAddr,(long)vmAddr);
        }
    }
    
//    atos -o [dsym file path] -l [Load Address] -arch [arch type] [Stack Address]
}
@end
