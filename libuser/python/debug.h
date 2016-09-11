#ifndef debug_h
#define debug_h

#include <glib.h>

#undef  DEBUG_BINDING
#ifdef  DEBUG
#define DEBUG_BINDING
#endif

#ifdef DEBUG_BINDING
extern int indent G_GNUC_INTERNAL;
char *getindent() G_GNUC_INTERNAL;
#define DEBUG_ENTRY {\
	fprintf(stderr, "%sEntering `%s' at line %d.\n", \
		getindent(), __FUNCTION__, __LINE__); \
	indent++; \
	}
#define DEBUG_CALL {\
      	fprintf(stderr, "%sIn `%s' at line %d.\n", \
		getindent(), __FUNCTION__, __LINE__); \
	}
#define DEBUG_EXIT {\
	indent--; \
	fprintf(stderr, "%sLeaving `%s' at line %d.\n", \
		getindent(), __FUNCTION__, __LINE__); \
	}
#else
#define DEBUG_ENTRY
#define DEBUG_CALL
#define DEBUG_EXIT
#endif

#endif
