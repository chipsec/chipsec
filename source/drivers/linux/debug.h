/// Contains macro for debug output.
/**
 * @file
 */

#ifndef _DEBUG_H
#define _DEBUG_H


/// if defined debug is enabled
#define DEBUG

#ifdef DEBUG 
/// Macro for debug print
#define dbgprint(format, args...) \
	do {            \
		printk(KERN_DEBUG "%s %s %d: "format"\n", program_name, __FUNCTION__, __LINE__, ## args);\
	} while ( 0 )
#else
#define dbgprint(format, args...) do {} while( 0 );
#endif

#endif
