#define _GNU_SOURCE
#include <sched.h>
#include <errno.h>

#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <asm/types.h>
#include <linux/types.h>
#define u64 uint64_t
#include "../../../../drivers/linux/include/chipsec.h"

#define BUF_LEN 4096

void print_cpu_set_t(cpu_set_t mask);

unsigned int getaffinity(unsigned long int NumCPUS, unsigned long int* maskArray[], int *errno_var){
    cpu_set_t mask;
	CPU_ZERO(&mask);
    *errno_var=0;
	if (0 == sched_getaffinity(0, sizeof(mask), &mask)){
         long li;
         for ( li = 0; li <NumCPUS; li++) {
                unsigned long int valueMask=0;
                if (CPU_ISSET(li, &mask)) {
                   valueMask=1;
                }
                 *(unsigned long int*)maskArray=valueMask;
                  maskArray++;
            }
        return 0;
	}else{ 
		*errno_var=errno;
        return 1;
    }
}

int setaffinity(int thread_id, int *errno_var){	
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(thread_id, &mask);
	if(0 != sched_setaffinity(0, sizeof(mask), &mask)){
        *errno_var=errno;
		return -1;
    }else{ 
    return 0;
    }
}
   
 void print_cpu_set_t(cpu_set_t mask){
    int i=0;
    for(i;i<sizeof(mask);i++){
        printf("%lu ",(unsigned long)mask.__bits[i]);
    }
    printf("\n\n");
}
