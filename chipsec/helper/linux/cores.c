/*
CHIPSEC: Platform Security Assessment Framework
Copyright (c) 2010-2014, Intel Corporation

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; Version 2.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

Contact information:
chipsec@intel.com
*/

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
   
