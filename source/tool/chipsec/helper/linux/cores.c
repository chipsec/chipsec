#include "Python.h"
#include <sched.h>
#include <errno.h>

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
