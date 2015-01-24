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
/* Not using currently
unsigned long getaffinity(){
	cpu_set_t mask;
	if(0 != sched_getaffinity(0, sizeof(mask), &mask))
		return errno;
	else return &mask;
}
*/

int setaffinity(int thread_id){	
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(thread_id, &mask);
	if(0 != sched_setaffinity(0, sizeof(mask), &mask))
		return errno;
	else return 0;
}