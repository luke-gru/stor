#ifndef _STOR_H_
#define _STOR_H_

// for strnlen
#define _POSIX_C_SOURCE 200809L

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
    CMD_UPDATE,
    CMD_DELETE,
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
    DBERR_COLNAME_NOEXIST,
    DBERR_COLTYPE_INVALID,
    DBERR_TOO_MANY_REC_VALUES,
    DBERR_VAL_OUT_OF_RANGE,
    DBERR_MISSING_FIND_VALUE,
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
    coltype_t type;
} dbtval_t;
typedef vec_t(dbtval_t) vec_dbtval_t;

// tagged value type for a specific table and column, used in searches
typedef struct dbsrchcrit {
    tblid_t tbl_id;
    colid_t col_id;
    int col_idx;
    dbval_t val;
    coltype_t type;
} dbsrchcrit_t;
typedef vec_t(dbsrchcrit_t) vec_dbsrchcrit_t;

typedef struct dbsrchopt {
    unsigned long limit;
} srchopt_t;

typedef struct dbupdval {
    tblid_t tbl_id;
    colid_t col_id;
    int col_idx;
    dbval_t newval;
    ssize_t size_diff;
    coltype_t type;
} dbupdval_t;
typedef vec_t(dbupdval_t) vec_dbupdval_t;

static inline const char const *dbstrerr(dberr_t err) {
    switch (err) {
    case DBERR_TBLNAME_TOO_LONG:
        return "Table name too long";
    case DBERR_TBLNAME_EXISTS:
        return "Table already exists with that name";
    case DBERR_TBLNAME_NOEXIST:
        return "Table doesn't exist with that name";
    case DBERR_COLNAME_TOO_LONG:
        return "Column name too long";
    case DBERR_COLNAME_NOEXIST:
        return "Column doesn't exist";
    case DBERR_COLTYPE_INVALID:
        return "Column type invalid";
    case DBERR_TOO_MANY_REC_VALUES:
        return "Too many record values";
    case DBERR_VAL_OUT_OF_RANGE:
        return "Value out of range";
    case DBERR_MISSING_FIND_VALUE:
        return "Missing value for find";
    default:
        return "Unknown";
    }
}


#define DB_COL_SER_BYTES(colp) (sizeof(*colp))
typedef struct stordb_col {
    colid_t col_id;
    coltype_t col_type;
    char col_name[STOR_COLNAME_MAX];
} PACKED col_t;

typedef vec_t(struct stordb_col) vec_col_t;
typedef vec_t(uint16_t) vec_blknum_t;

#define DB_TBL_SER_BYTES_PRELOAD(tblp) (sizeof(*tblp))
#define DB_TBL_SER_BYTES_POSTLOAD(tblp) (\
        DB_TBL_SER_BYTES_PRELOAD(tblp)+(tblp->tbl_num_cols*sizeof(struct stordb_col))\
        +(tblp->tbl_num_blks*sizeof(uint16_t)))
typedef struct stordb_tbl {
    tblid_t tbl_id;
    char tbl_name[STOR_TBLNAME_MAX];
    uint16_t tbl_num_cols;
    uint16_t tbl_num_blks;
    vec_col_t tbl_cols;
    vec_blknum_t tbl_blks;
} PACKED tbl_t;

typedef vec_t(struct stordb_tbl*) vec_tblp_t;

#define DB_META_SER_BYTES(metap) (sizeof(*metap) - sizeof((metap)->mt_tbls))
typedef struct stordb_meta {
    uint16_t mt_magic;
    uint16_t mt_num_tables;
    size_t mt_sersize; // meta info serialized size, including all serialized tables
    vec_tblp_t mt_tbls;
} PACKED meta_t;

typedef struct db_tagged_err {
    dberr_t err;
    char *msg;
} dbterr_t;

// block header
// Since records are not fixed length, they're added to the end of
// the block first, and grow up towards the header as they're added.
typedef struct stordb_blk_h {
    uint16_t bh_magic;
    uint16_t bh_blkno;
    tblid_t bh_tbl_id;
    uint16_t bh_free;
    uint16_t bh_num_records;
    uint16_t bh_record_offsets[];
} PACKED blkh_t;

typedef vec_t(struct stordb_blk_h*) vec_blkp_t;

typedef struct stordb {
    const char *db_fname;
    int db_fd;
    off_t db_offset;
    bool db_mt_dirty;
    struct db_tagged_err db_lasterr;
    vec_blkp_t db_blkcache;
    vec_int_t db_blksdirty;
    struct stordb_meta db_meta;
} db_t;

#define REC_VALUES_PTR(recp) (((char*)(recp))+(recp->header.rech_sz))
#define REC_VALUE_PTR(recp,n) (((char*)(recp))+(recp->header.rech_sz+recp->header.rec_offsets[n]))
#define REC_SZ(recp) (recp->header.rech_sz+recp->header.rec_sz)
#define REC_H_TOMBSTONE_VALUE (SIZE_MAX)
#define REC_IS_TOMBSTONED(recp) (*(size_t*)recp == REC_H_TOMBSTONE_VALUE)
typedef struct stordb_rec_h {
    size_t rech_sz; // size of record header
    size_t rec_sz; // size of record not including the header
    off_t rec_offsets[]; // values[] offsets for sorted columns
} PACKED rech_t;
typedef struct stordb_rec {
    struct stordb_rec_h header;
    unsigned char values[];
} PACKED rec_t;
typedef vec_t(rec_t*) vec_recp_t;

typedef struct stordb_recinfo {
    blkh_t *blk;
    rec_t *rec;
} recinfo_t;
typedef vec_t(recinfo_t) vec_recinfo_t;

#define BLK_RECORDS_FOREACH(blkh, var, idx)\
for ((idx) = 0;\
    ((idx) < (blkh)->bh_num_records) &&\
    (var = (struct stordb_rec*)(((char*)(blkh))+blkh->bh_record_offsets[idx]));\
    idx++)

void die(const char *fmt, ...);
int db_init(db_t *db);
int db_load(db_t *db);
int db_add_table(db_t *db, const char *tblname, const char *colinfo, dberr_t *dberr);
blkh_t *db_find_blk_for_rec(db_t *db, tbl_t *tbl, size_t recsz, bool alloc_if_not_found, bool *isnewblk);
int db_add_record(db_t *db, const char *tblname, const char *rowvals, blkh_t **blkh_out, bool flushblk, dberr_t *dberr);
int db_parse_srchcrit(db_t *db, tbl_t *tbl, const char *srchcrit_str, vec_dbsrchcrit_t *vsearch_crit, dberr_t *dberr);
tbl_t *db_find_table(db_t *db, const char *tblname);
int db_find_records(db_t *db, tbl_t *tbl, vec_dbsrchcrit_t *vsearch_crit, srchopt_t *options, vec_recinfo_t *vrecinfo_out, dberr_t *dberr);
int db_update_records(db_t *db, vec_recinfo_t *vrecinfo, vec_dbsrchcrit_t *vupdate_info, dberr_t *dberr);
int db_delete_records(db_t *db, vec_recinfo_t *vrecinfo, dberr_t *dberr);
int db_find_record(db_t *db, tbl_t *tbl, vec_dbsrchcrit_t *vsearch_crit, recinfo_t *recinfo_out, dberr_t *dberr);
blkh_t *db_load_blk(db_t *db, uint16_t num);
tbl_t *db_table(db_t *db, int i);
col_t *db_col(tbl_t *tbl, int i);
int db_flush_meta(db_t *db);
int db_close(db_t *db);

const char *coltype_str(coltype_t coltype);

#endif
