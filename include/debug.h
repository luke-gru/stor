#ifndef _STOR_DEBUG_H_
#define _STOR_DEBUG_H_

// debug bit flags
#define DBG_SCHEMA 0x00001
#define DBG_INSERT 0x00002

extern uint32_t stor_dbgflags;

#define LOG_ERR(...) (fprintf(stderr, "[ERROR] " __VA_ARGS__))
#define DEBUG(d, ...) ((stor_dbgflags & (d)) ? fprintf(stderr, "[DEBUG] " __VA_ARGS__) : 0)

#endif
