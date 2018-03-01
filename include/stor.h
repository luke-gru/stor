#ifndef _STOR_H_
#define _STOR_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <limits.h>
#include <math.h>
#include "debug.h"
#include "list.h"
#include "strdup.h"
#include "vec.h"

#define ASSERT(expr) ((expr) ? (void)0 : die("assertion failure (%s:%d) in %s\n", __FILE__, __LINE__, __func__))

#define PACKED __attribute__ ((packed))
#define STOR_BLKSIZ 4096
#define STOR_META_MAGIC 0xbeef
#define STOR_BLKH_MAGIC 0xfeed
#define STOR_TBLNAME_MAX 30
#define STOR_COLNAME_MAX 30
#define STOR_COLTYPE_MAX 10
#define STOR_VARCHAR_MAX 255

typedef enum stor_cmd {
    CMD_CREATE = 1,
    CMD_FIND,
    CMD_LOAD,
    CMD_ADDTBL,
    CMD_ADDREC,
} cmd_t;

typedef enum stor_coltype {
    COLTYPE_ERR = 0,
    COLTYPE_INT,
    COLTYPE_CHAR,
    COLTYPE_VARCHAR,
    COLTYPE_DOUBLE,
} coltype_t;

typedef unsigned short tblid_t;
typedef unsigned short colid_t;
typedef enum dberr_t {
    DBERR_UNKNOWN = 0,
    DBERR_TBLNAME_TOO_LONG,
    DBERR_TBLNAME_EXISTS,
    DBERR_TBLNAME_NOEXIST,
    DBERR_COLNAME_TOO_LONG,
    DBERR_COLTYPE_INVALID,
    DBERR_TOO_MANY_REC_VALUES,
    DBERR_VAL_OUT_OF_RANGE,
} dberr_t;


typedef union dbval {
    char cval;
    int ival;
    char *sval;
    double dval;
} dbval_t;

// tagged value type
typedef struct dbtval {
    dbval_t val;
    enum stor_coltype type;
} dbtval_t;

static inline const char const *dbstrerr(dberr_t err) {
    switch (err) {
    case DBERR_UNKNOWN:
        return "Unknown";
    case DBERR_TBLNAME_TOO_LONG:
        return "Table name too long";
    case DBERR_TBLNAME_EXISTS:
        return "Table already exists with that name";
    case DBERR_TBLNAME_NOEXIST:
        return "Table doesn't exist with that name";
    case DBERR_COLNAME_TOO_LONG:
        return "Column name too long";
    case DBERR_COLTYPE_INVALID:
        return "Column type invalid";
    case DBERR_TOO_MANY_REC_VALUES:
        return "Too many record values";
    case DBERR_VAL_OUT_OF_RANGE:
        return "Value out of range";
    default:
        return "Unknown";
    }
}


#define DB_COL_SER_BYTES(colp) (sizeof(*colp))
struct stordb_col {
    colid_t col_id;
    coltype_t col_type;
    char col_name[STOR_COLNAME_MAX];
} PACKED;

typedef vec_t(struct stordb_col) vec_col_t;
typedef vec_t(uint16_t) vec_blknum_t;

#define DB_TBL_SER_BYTES_PRELOAD(tblp) (sizeof(*tblp))
#define DB_TBL_SER_BYTES_POSTLOAD(tblp) (\
        DB_TBL_SER_BYTES_PRELOAD(tblp)+(tblp->tbl_num_cols*sizeof(struct stordb_col))\
        +(tblp->tbl_num_blks*sizeof(uint16_t)))
struct stordb_tbl {
    tblid_t tbl_id;
    char tbl_name[STOR_TBLNAME_MAX];
    uint16_t tbl_num_cols;
    uint16_t tbl_num_blks;
    vec_col_t tbl_cols;
    vec_blknum_t tbl_blks;
} PACKED;

typedef vec_t(struct stordb_tbl*) vec_tblp_t;

#define DB_META_SER_BYTES(metap) (sizeof(*metap) - sizeof(vec_tblp_t))
struct stordb_meta {
    uint16_t mt_magic;
    uint16_t mt_num_tables;
    size_t mt_sersize; // meta info serialized size, including all serialized tables
    vec_tblp_t mt_tbls;
} PACKED;

struct db_tagged_err {
    dberr_t err;
    char *msg;
};

// block header
// Since records are not fixed length, they're added to the end of
// the block first, and grow up towards the header as they're added.
struct stordb_blk_h {
    uint16_t bh_magic;
    uint16_t bh_blknum;
    tblid_t bh_tbl_id;
    uint16_t bh_free;
    uint16_t bh_num_records;
    uint16_t bh_record_offsets[];
} PACKED;

typedef vec_t(struct stordb_blk_h*) vec_blkp_t;

struct stordb {
    const char *db_fname;
    int db_fd;
    off_t db_offset;
    bool db_mt_dirty;
    struct db_tagged_err db_lasterr;
    vec_blkp_t db_blkcache;
    struct stordb_meta db_meta;
};

struct stordb_rec_h {
    size_t rech_sz; // size of record header
    size_t rec_sz; // size of record not including the header
    off_t rec_offsets[];
} PACKED;
struct stordb_rec {
    struct stordb_rec_h header;
    unsigned char values[];
} PACKED;


void die(const char *fmt, ...);
int init_db(struct stordb*);

#endif
