//
// Chipsec OSX kernel driver - Test suite
// Tested on MacBookAir6,2
//
// Copyright 2016 Google Inc. All Rights Reserved.
// Author: Thiebaud Weksteen (tweksteen@gmail.com)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "chipsec_ioctl.h"

typedef int (*test)(int);

int test_pci_ioctl(int dev_chipsec){
    pci_msg_t data;

    printf("Testing PCI ioctl...");

    data.bus = 0;
    data.device = 0x0;
    data.function = 0x0;
    data.offset = 0x30;
    data.length = 4;
    data.value = 0xdeadbeef;

    /* Reading 0:0.0 at offset 0x30, that is BAR0 */
    ioctl(dev_chipsec, CHIPSEC_IOC_RDPCI, &data);
    if(data.value == 0xdeadbeef) {
        printf("Error: RDPCI failed\n");
        return -1;
    }

    /* Reset BAR0 */
    data.value = 0xFFFFFFFF;
    ioctl(dev_chipsec, CHIPSEC_IOC_WRPCI, &data);

    /* Read the value again */
    ioctl(dev_chipsec, CHIPSEC_IOC_RDPCI, &data);
    if(data.value == 0xFFFFFFFF) {
        printf("Error: WRPCI failed\n");
        return -1;
    }

    return 0;
}

int test_mmio_ioctl(int dev_chipsec)
{
    mmio_msg_t data;
    uint64_t original_value;

    printf("Testing MMIO ioctl...");

    /* SPIBAR FDATA0 */
    data.addr = 0xFED1F810;
    data.length = 4;
    ioctl(dev_chipsec, CHIPSEC_IOC_RDMMIO, &data);
    original_value = data.value;

    /* Test the 4-bytes write/read */
    data.addr = 0xFED1F810;
    data.length = 4;
    data.value = 0xdeadbeef;
    ioctl(dev_chipsec, CHIPSEC_IOC_WRMMIO, &data);

    data.value = 0;
    data.addr = 0xFED1F810;
    data.length = 4;
    ioctl(dev_chipsec, CHIPSEC_IOC_RDMMIO, &data);
    if(data.value != 0xdeadbeef) {
        printf("Error: MMIO 4-bytes Read/Write failed\n");
        return -1;
    }

    /* Test the 2-bytes write/read */
    data.addr = 0xFED1F810;
    data.length = 2;
    data.value = 0xcafe;
    ioctl(dev_chipsec, CHIPSEC_IOC_WRMMIO, &data);

    data.value = 0;
    data.addr = 0xFED1F810;
    data.length = 2;
    ioctl(dev_chipsec, CHIPSEC_IOC_RDMMIO, &data);
    if(data.value != 0xcafe) {
        printf("Error: MMIO 2-bytes Read/Write failed\n");
        return -1;
    }

    /* Test the 1-byte write/read */
    data.addr = 0xFED1F810;
    data.length = 1;
    data.value = 0xee;
    ioctl(dev_chipsec, CHIPSEC_IOC_WRMMIO, &data);

    data.value = 0;
    data.addr = 0xFED1F810;
    data.length = 1;
    ioctl(dev_chipsec, CHIPSEC_IOC_RDMMIO, &data);
    if(data.value != 0xee) {
        printf("Error: MMIO 1-byte Read/Write failed\n");
        return -1;
    }

    /* Restore initial value */
    data.value = original_value;
    data.addr = 0xFED1F810;
    data.length = 4;
    ioctl(dev_chipsec, CHIPSEC_IOC_WRMMIO, &data);
    return 0;
}

int test_cr_ioctl(int dev_chipsec)
{
    unsigned int i;
    cr_msg_t data;
    short valid_cr[] = { 0, 2, 3, 4, 8};
    unsigned int len = sizeof(valid_cr)/sizeof(short);

    printf("Testing CR ioctl...");

    /* Read all the implemented CR register */
    for(i=0; i<len; i++){
        data.register_number = valid_cr[i];
        ioctl(dev_chipsec, CHIPSEC_IOC_RDCR, &data);
    }

    return 0;
}

int main(int argc, const char * argv[])
{
    int i, ret, dev_chipsec;
    unsigned int num_tests;
    test t = NULL;
    test tests[] = { &test_pci_ioctl, &test_mmio_ioctl, &test_cr_ioctl };

    dev_chipsec = open("/dev/chipsec", O_RDWR);
    num_tests = sizeof(tests)/sizeof(test);

    for(i=0; i<num_tests; i++){
        t = tests[i];
        ret = t(dev_chipsec);
        if(ret) {
            printf("Failure\n");
        }
        else {
            printf("Success\n");
        }
    }
}
