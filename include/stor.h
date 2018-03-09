#ifndef _STOR_H_
#define _STOR_H_

// for strnlen
#define _POSIX_C_SOURCE 200809L

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
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
#include "kstrdup.h"
#include "vec.h"

#define ASSERT(expr) ((expr) ? (void)0 : die("assertion failure (%s:%d) in %s\n", __FILE__, __LINE__, __func__))
#define ASSERT_MEM(expr) ASSERT(expr)

#define PACKED __attribute__ ((packed))
#define STOR_PAGESZ 4096
#define STOR_META_MAGIC 0xbeef
#define STOR_BLKH_MAGIC 0xfeed
#define STOR_BLKH_TOMBSTONE 0xbabe
#define STOR_TBLNAME_MAX 30
#define STOR_COLNAME_MAX 30
#define STOR_COLTYPE_MAX 20
#define STOR_VARCHAR_MAX 255
#define STOR_MAX_TBL_COLS 1024

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

// qualified column type
typedef struct {
    coltype_t type;
    size_t size;
} qcoltype_t;

typedef unsigned short tblid_t;
typedef unsigned short colid_t;
typedef enum dberr_t {
    DBERR_UNKNOWN = 0,
    DBERR_DBNAME_INVALID,
    DBERR_DB_NOT_OPEN,
    DBERR_LOADING_METAINFO,
    DBERR_TBLNAME_TOO_LONG,
    DBERR_TBLNAME_EXISTS,
    DBERR_TBLNAME_NOEXIST,
    DBERR_COLNAME_TOO_LONG,
    DBERR_COLNAME_NOEXIST,
    DBERR_COLTYPE_INVALID,
    DBERR_TOO_MANY_REC_VALUES,
    DBERR_VAL_OUT_OF_RANGE,
    DBERR_MISSING_FIND_VALUE,
    DBERR_SEEK_ERR,
    DBERR_PARSE_ERR,
    DBERR_INVALID_BLOCK_OVERWRITE,
    DBERR_ERRNO,
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
    qcoltype_t qtype;
} dbtval_t;
typedef vec_t(dbtval_t) vec_dbtval_t;

// tagged value type for a specific table and column, used in searches
typedef struct dbsrchcrit {
    tblid_t tbl_id;
    colid_t col_id;
    int col_idx;
    dbval_t val;
    qcoltype_t qtype;
} dbsrchcrit_t;
typedef vec_t(dbsrchcrit_t) vec_dbsrchcrit_t;

typedef struct dbsrchopt {
    unsigned long limit;
} srchopt_t;

static inline const char const *dbstrerr(dberr_t err) {
    switch (err) {
    case DBERR_DBNAME_INVALID:
        return "Invalid database name given";
    case DBERR_LOADING_METAINFO:
        return "Error loading meta info for database. Possibly corrupted?";
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
    case DBERR_SEEK_ERR:
        return "File seek error";
    case DBERR_PARSE_ERR:
        return "Parse error";
    case DBERR_INVALID_BLOCK_OVERWRITE:
        return "Can't overwrite file block";
    case DBERR_ERRNO:
        return "Error with system call or library function. Check errno for details.";
    default:
        return "Unknown";
    }
}


#define DB_COL_SER_BYTES(colp) (sizeof(*colp))
typedef struct stordb_col {
    colid_t col_id;
    qcoltype_t qcol_type;
    char col_name[STOR_COLNAME_MAX];
} PACKED col_t;

typedef vec_t(col_t) vec_col_t;
typedef vec_t(uint16_t) vec_blkno_t;

#define DB_TBL_SER_BYTES_PRELOAD(tblp) (sizeof(*tblp))
#define DB_TBL_SER_BYTES_POSTLOAD(tblp) (\
        DB_TBL_SER_BYTES_PRELOAD(tblp)+((tblp)->tbl_num_cols*sizeof(col_t))\
        +((tblp)->tbl_num_blks*sizeof(uint16_t)))
typedef struct stordb_tbl {
    tblid_t tbl_id;
    char tbl_name[STOR_TBLNAME_MAX];
    uint16_t tbl_num_cols;
    uint16_t tbl_num_blks;
    vec_col_t tbl_cols;
    vec_blkno_t tbl_blknos;
} PACKED tbl_t;

typedef vec_t(tbl_t*) vec_tblp_t;

typedef struct db_tagged_err {
    dberr_t err;
    char *msg;
    int err_errno;
} dbterr_t;

// block header
// Since records are not fixed length, they're added to the end of
// the block first, and grow up towards the header as they're added.
typedef struct stordb_blk_h {
    uint16_t bh_magic;
    uint16_t bh_blkno;
    uint16_t bh_nextblkno; // for segmented blocks
    tblid_t bh_tbl_id;
    uint16_t bh_free;
    uint16_t bh_num_records; // num records in this page (doesn't count records in subsequent pages)
    // NOTE: offsets are from the start of the block header, NOT from the start of this array
    uint16_t bh_record_offsets[];
} PACKED blkh_t;
typedef vec_t(blkh_t*) vec_blkp_t;

#define DB_META_SER_BYTES(metap) (sizeof(*metap) - (sizeof((metap)->mt_tbls)+sizeof((metap)->mt_blks)))
typedef struct stordb_meta { // beginning of meta info (always starts at blk #0)
    uint16_t mt_magic;
    uint16_t mt_num_tables;
    size_t mt_sersize; // meta info serialized size, including all serialized tables
    uint16_t mt_nextblkno; // when mt_sersize > STOR_PAGESZ, this is non-zero.
    vec_tblp_t mt_tbls;
    vec_blkp_t mt_blks; // when mt_sersize > STOR_PAGESZ, we keep track of all extra blocks for meta info
} PACKED meta_t;

#define REC_VALUES_PTR(recp) (PTR(recp)+(recp->header.rech_sz))
#define REC_VALUE_PTR(recp,n) (PTR(recp)+(recp->header.rech_sz+recp->header.rec_offsets[(n)]))
#define REC_SZ(recp) (recp->header.rech_sz+recp->header.rec_sz)
#define REC_H_TOMBSTONE_VALUE (SIZE_MAX)
#define REC_IS_TOMBSTONED(recp) (*(size_t*)recp == REC_H_TOMBSTONE_VALUE)
typedef struct stordb_rec_h {
    size_t rech_sz; // size of record header
    size_t rec_sz; // size of record not including the header
    off_t rec_offsets[]; // values[] offsets for sorted columns
} PACKED rech_t;
typedef struct stordb_rec {
    rech_t header;
    unsigned char values[];
} PACKED rec_t;
typedef vec_t(rec_t*) vec_recp_t;

typedef struct stordb_recinfo {
    blkh_t *blk;
    rec_t *rec;
} recinfo_t;
typedef vec_t(recinfo_t) vec_recinfo_t;

typedef struct stordb_blkdata {
    blkh_t *blk;
    uint16_t blkoff;
    uint16_t datasz;
} blkdata_t;
typedef vec_t(blkdata_t) vec_blkdata_t;

typedef struct stordb_blkinfo {
    blkh_t *blk;
    vec_blkdata_t blk_holes;
    bool holes_computed; // is the blk hole info up-to-date (it's lazily computed, on demand)
    bool is_dirty;
} blkinfo_t;
typedef vec_t(blkinfo_t) vec_blkinfo_t;

typedef struct stordb {
    const char *db_fname;
    int db_fd;
    off_t db_offset;
    bool db_mt_dirty;
    struct db_tagged_err db_lasterr;
    unsigned db_num_writes;
    bool db_mem_only;
    vec_blkp_t db_blkcache; // data blocks loaded into memory
    vec_int_t db_blksdirty; // data blocks needing to be written back to disk
    vec_blkinfo_t db_vblkinfo; // cached info on data blocks, such as computed holes, etc.
    meta_t db_meta;
} db_t;

#define BLK_RECORDS_FOREACH(blkh, var, idx)\
for ((idx) = 0;\
    ((idx) < (blkh)->bh_num_records) &&\
    (var = (rec_t*)(PTR(blkh)+blkh->bh_record_offsets[idx]));\
    idx++)

#define PTR(ptr) ((char*)(ptr))

#define BLK_FITS_RECSZ(blkh,recsz) ((blkh)->bh_free >= (recsz+sizeof(uint16_t)))
#define BLK_CONTAINS_REC(blkh,recp) ((PTR(recp))-PTR((blkh)) > 0 && (PTR(recp))-(PTR(blkh)) < STOR_PAGESZ)
#define BLKH_SIZE(blkh) (sizeof(*blkh)+(blkh->bh_num_records*sizeof(uint16_t)))
#define BLK_END(blkp) (PTR(blkp)+STOR_PAGESZ)
#define BLK_FREE_INITIAL (STOR_PAGESZ-sizeof(blkh_t))

int db_create(db_t *db, dberr_t *dberr);
int db_open(db_t *db, dberr_t *dberr);
int db_close(db_t *db, dberr_t *dberr);
int db_clear(db_t *db, dberr_t *dberr);
int db_add_table(db_t *db, const char *tblname, const char *colinfo, bool flush_to_disk, dberr_t *dberr);
blkh_t *db_find_blk_for_rec(db_t *db, tbl_t *tbl, size_t recsz, bool alloc_if_not_found, uint16_t *blk_offset, bool *isnewblk);
int db_drop_table(db_t *db, tbl_t *tbl, bool clear_blks, bool flush_to_disk, dberr_t *dberr);
int db_add_record(db_t *db, const char *tblname, const char *rowvals, blkh_t **blkh_out, bool flushblk, dberr_t *dberr);
int db_parse_srchcrit(db_t *db, tbl_t *tbl, const char *srchcrit_str, vec_dbsrchcrit_t *vsearch_crit, dberr_t *dberr);
int db_find_records(db_t *db, tbl_t *tbl, vec_dbsrchcrit_t *vsearch_crit, srchopt_t *options, vec_recinfo_t *vrecinfo_out, dberr_t *dberr);
int db_update_records(db_t *db, vec_recinfo_t *vrecinfo, vec_dbsrchcrit_t *vupdate_info, dberr_t *dberr);
int db_delete_records(db_t *db, vec_recinfo_t *vrecinfo, dberr_t *dberr);
int db_find_record(db_t *db, tbl_t *tbl, vec_dbsrchcrit_t *vsearch_crit, recinfo_t *recinfo_out, dberr_t *dberr);
int db_move_record_to_blk(db_t *db, rec_t *rec, blkh_t *oldblk, blkh_t *newblk, uint16_t newrec_blkoff, rec_t **rec_out, dberr_t *dberr);
blkh_t *db_load_blk(db_t *db, uint16_t num, bool restore_dboffset);
blkh_t *db_alloc_blk(db_t *db, uint16_t num, tbl_t *tbl, bool allow_overwrite, dberr_t *dberr);
int db_clear_blk(db_t *db, uint16_t num, dberr_t *dberr);
uint16_t db_next_blkno(db_t *db, dberr_t *dberr);
tbl_t *db_table_from_idx(db_t *db, int idx);
tbl_t *db_table_from_id(db_t *db, tblid_t tblid);
tbl_t *db_table_from_name(db_t *db, const char *tblname);
col_t *db_col_from_idx(tbl_t *tbl, int idx);
col_t *db_col_from_name(tbl_t *tbl, const char *name, int *colidx);
int db_flush_meta(db_t *db, dberr_t *dberr);
int db_flush_dirty_blks(db_t *db);

rec_t *BLK_LAST_REC(blkh_t *blk);
rec_t *BLK_FIRST_REC(blkh_t *blk);
rec_t *BLK_NTH_REC(blkh_t *blk, int n);
void blk_find_holes(db_t *db, blkh_t *blk, vec_blkdata_t *vholes, bool force_recompute);
void blk_mark_hole_filled(db_t *db, blkh_t *blk, vec_blkdata_t *vholes, uint16_t fill_start, uint16_t fill_end);
void blk_mark_new_hole(db_t *db, blkh_t *blk, vec_blkdata_t *vholes, uint16_t hole_start, uint16_t hole_end);
void db_grow_record_within_blk(blkh_t *blk, rec_t *rec, col_t *col, void *rec_newstart, dbsrchcrit_t *update_info, size_t diffsz);
int  db_blk_cpy_rec(db_t *db, blkh_t *blk, rec_t *rec, uint16_t blk_off, rec_t **recout);
blkinfo_t *db_blkinfo(db_t *db, blkh_t *blk);


dbval_t REC_DBVAL(rec_t *rec, int colidx, coltype_t type);
void *DBVAL_PTR(dbval_t *dbval, coltype_t type);
size_t DBVAL_SZ(dbval_t *val, qcoltype_t *qtype);
const char *coltype_str(qcoltype_t *qcoltype);
int db_coltype(db_t *db, char *coltype_str, qcoltype_t *qtype_out, dberr_t *dberr);

void db_log_lasterr(db_t *db);
void die(const char *fmt, ...);

#endif
