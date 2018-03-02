#ifndef _STOR_DEBUG_H_
#define _STOR_DEBUG_H_

// debug bit flags
#define DBG_SCHEMA  0x00001
#define DBG_ADD     0x00002
#define DBG_SRCH    0x00004
#define DBG_STATE   0x00008
#define DBG_DESER   0x00010
#define DBG_UPDATE  0x00020
#define DBG_INDEX   0x00040
#define DBG_CACHE   0x00080
#define DBG_DEL     0x00100

#define DBG_ALL     0xFFFFF
#define DBG_NONE    0x00000

extern uint32_t stor_dbgflags;

#define LOG_ERR(...) (fprintf(stderr, "[ERROR] " __VA_ARGS__))

#ifndef NDEBUG
#define DEBUG(d, ...) ((stor_dbgflags & (d)) ? fprintf(stderr, "[DEBUG] " __VA_ARGS__) : 0)
#define DEBUGASSERT(expr) ASSERT(expr)
#else
#define DEBUG(d, ...) (void(0))
#define DEBUGASSERT(expr) ((void)0)
#endif

#endif
