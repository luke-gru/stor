#include <stor.h>

uint32_t stor_dbgflags;
static char empty_page[STOR_PAGESZ];

void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(1);
}

static void db_set_lasterr(db_t *db, dberr_t *dberr, char *msg) {
    db->db_lasterr.err = *dberr;
    if (db->db_lasterr.msg) {
        free(db->db_lasterr.msg);
    }
    db->db_lasterr.msg = msg; // can be NULL
    if (*dberr == DBERR_ERRNO) {
        db->db_lasterr.err_errno = errno;
    } else {
        db->db_lasterr.err_errno = 0;
    }
}

static int create_dbfile(const char *fname) {
    int fd = open(fname, O_RDWR|O_CREAT|O_EXCL, 0644);
    if (fd == -1) {
        return -1; // errno set
    }
    return fd;
}

static int db_seek(db_t *db, int whence, off_t offset) {
    ASSERT(db->db_fd > 0);
    if (db->db_offset == offset && whence == SEEK_SET) {
        return 0;
    }
    off_t res = lseek(db->db_fd, offset, whence);
    if (res == -1) {
        return -1; // errno set
    }
    db->db_offset = res;
    return 0;
}

static ssize_t db_write(db_t *db, void *buf, size_t bufsize) {
    if (db->db_mem_only) {
        db->db_offset += bufsize;
        db->db_num_writes++;
        return bufsize;
    }
    ASSERT(db->db_fd > 0);
    ssize_t res = write(db->db_fd, buf, bufsize);
    if (res == -1) return res;
    if (res != bufsize) return -1;
    db->db_offset += res;
    db->db_num_writes++;
    return res;
}

static ssize_t db_read(db_t *db, void *buf, size_t bufsize) {
    ASSERT(db->db_fd > 0);
    ssize_t res = read(db->db_fd, buf, bufsize);
    if (res == -1) return res;
    db->db_offset += res;
    return res;
}

static int io_crosses_page_boundary(db_t *db, size_t io_bytelen) {
    int curpage = db->db_offset / STOR_PAGESZ;
    int afterpage = (db->db_offset+io_bytelen) / STOR_PAGESZ;
    if (curpage == afterpage) { // same page
        return 0;
    } else {
        return (db->db_offset+io_bytelen) % STOR_PAGESZ; // return IO bytes remaining for next page
    }
}

static int db_load_next_table(db_t *db, blkh_t *nextblk, blkh_t **blockloadedfrom) {
    tbl_t *tbl = malloc(sizeof(*tbl));
    ASSERT_MEM(tbl);
    memset(tbl, 0, sizeof(*tbl));
    int bytes_rem = 0;

    size_t tbl_preload_sz = DB_TBL_SER_BYTES_PRELOAD(tbl);
    int res;
    // ex: db_offset: 8100, tbl_preload_sz: 100, page size: 4096, read is
    // split across this block and next meta block.
    if ((bytes_rem = io_crosses_page_boundary(db, tbl_preload_sz)) > 0) {
        ASSERT(nextblk);
        DEBUG(DBG_TEST, "Read(1) crosses page boundary (db offset: %ld, size: %lu)\n", db->db_offset, tbl_preload_sz);
        if (tbl_preload_sz-bytes_rem > 0) {
            DEBUG(DBG_TEST, "First read(1) (db offset: %ld, size: %lu)\n", db->db_offset, tbl_preload_sz-bytes_rem);
            res = db_read(db, tbl, tbl_preload_sz-bytes_rem);
        }
        ASSERT(nextblk->bh_blkno*STOR_PAGESZ >= db->db_offset);
        res = db_seek(db, SEEK_SET, (nextblk->bh_blkno*STOR_PAGESZ)+sizeof(blkh_t));
        ASSERT(res == 0);
        DEBUG(DBG_TEST, "Second read(1) (db offset: %ld, size: %d)\n", db->db_offset, bytes_rem);
        *blockloadedfrom = nextblk;
        res = db_read(db, PTR(tbl)+(tbl_preload_sz-bytes_rem), bytes_rem);
    } else {
        DEBUG(DBG_TEST, "Direct read(1) (db offset: %ld, size: %lu)\n", db->db_offset, tbl_preload_sz);
        res = db_read(db, tbl, tbl_preload_sz);
    }
    if (res == -1) {
        DEBUG(DBG_TEST, "read(1) ERROR: %d\n", res);
        free(tbl);
        return res;
    }
    ASSERT(tbl->tbl_id > 0);
    DEBUG(DBG_TEST, "tbl_id: %u, tbl_num_cols: %u\n", tbl->tbl_id, tbl->tbl_num_cols);
    ASSERT(tbl->tbl_num_cols <= STOR_MAX_TBL_COLS);
    if (tbl->tbl_num_cols == 0) {
        DEBUG(DBG_TEST, "0 cols found for table name: %s\n", tbl->tbl_name);
    }
    vec_init(&tbl->tbl_cols);
    vec_init(&tbl->tbl_blknos);
    size_t tbl_postload_sz = DB_TBL_SER_BYTES_POSTLOAD(tbl);
    if (tbl_postload_sz > tbl_preload_sz) {
        tbl = realloc(tbl, tbl_postload_sz);
        ASSERT_MEM(tbl);
        size_t coldata_sz = sizeof(col_t)*tbl->tbl_num_cols;
        unsigned char *coldata = malloc(coldata_sz);
        ASSERT_MEM(coldata);

        DEBUG(DBG_TEST, "Coldata sz: %lu\n", coldata_sz);
        if ((bytes_rem = io_crosses_page_boundary(db, coldata_sz)) > 0) {
            ASSERT(nextblk);
            ASSERT(*blockloadedfrom != nextblk);
            DEBUG(DBG_TEST, "Read(2) crosses page boundary (db offset: %ld, size: %lu)\n", db->db_offset, coldata_sz);
            if (coldata_sz-bytes_rem > 0) {
                DEBUG(DBG_TEST, "First read(2) crosses page boundary (db offset: %ld, size: %lu)\n", db->db_offset, coldata_sz-bytes_rem);
                res = db_read(db, coldata, coldata_sz-bytes_rem);
            }
            res = db_seek(db, SEEK_SET, (nextblk->bh_blkno*STOR_PAGESZ)+sizeof(blkh_t));
            ASSERT(res == 0);
            *blockloadedfrom = nextblk;
            DEBUG(DBG_TEST, "Second read(2) (db offset: %ld, size: %d)\n", db->db_offset, bytes_rem);
            res = db_read(db, coldata+(coldata_sz-bytes_rem), bytes_rem);
        } else {
            DEBUG(DBG_TEST, "Direct read(2) (db offset: %ld, size: %lu)\n", db->db_offset, coldata_sz);
            res = db_read(db, coldata, coldata_sz);
        }
        if (res == -1) {
            DEBUG(DBG_TEST, "read(2) ERROR: %d\n", res);
            free(tbl); free(coldata);
            return res;
        }
        tbl->tbl_cols.data = (col_t*)coldata;
        tbl->tbl_cols.length = tbl->tbl_cols.capacity = tbl->tbl_num_cols;
        DEBUG(DBG_SCHEMA, "Loaded %d columns for tbl %s\n", tbl->tbl_num_cols, tbl->tbl_name);
        col_t *firstcol = (col_t*)coldata;
        DEBUG(DBG_SCHEMA, "first col type: %s, col name: %s\n", coltype_str(&firstcol->qcol_type), firstcol->col_name);
        if (tbl->tbl_num_blks > 0) {
            size_t blkdata_sz = sizeof(uint16_t)*tbl->tbl_num_blks;
            unsigned char *blkdata = malloc(blkdata_sz);
            ASSERT_MEM(blkdata);
            if ((bytes_rem = io_crosses_page_boundary(db, blkdata_sz)) > 0) {
                ASSERT(nextblk);
                ASSERT(*blockloadedfrom != nextblk);
                DEBUG(DBG_TEST, "Read(3) crosses page boundary (db offset: %ld, size: %lu)\n", db->db_offset, blkdata_sz);
                if (blkdata_sz-bytes_rem > 0) {
                    DEBUG(DBG_TEST, "First read(3) crosses page boundary (db offset: %ld, size: %lu)\n", db->db_offset, blkdata_sz-bytes_rem);
                    res = db_read(db, blkdata, blkdata_sz-bytes_rem);
                }
                res = db_seek(db, SEEK_SET, (nextblk->bh_blkno*STOR_PAGESZ)+sizeof(blkh_t));
                ASSERT(res == 0);
                *blockloadedfrom = nextblk;
                DEBUG(DBG_TEST, "Second read(3) crosses page boundary (db offset: %ld, size: %d)\n", db->db_offset, bytes_rem);
                res = db_read(db, blkdata+(blkdata_sz-bytes_rem), bytes_rem);
            } else {
                DEBUG(DBG_TEST, "Direct read(3) (db offset: %ld, size: %lu)\n", db->db_offset, blkdata_sz);
                res = db_read(db, blkdata, blkdata_sz);
            }
            if (res == -1) {
                DEBUG(DBG_TEST, "read(3) ERROR: %d\n", res);
                free(tbl); free(coldata); free(blkdata);
                return res;
            }
            tbl->tbl_blknos.data = (uint16_t*)blkdata;
            tbl->tbl_blknos.length = tbl->tbl_blknos.capacity = tbl->tbl_num_blks;
        }
    }
    vec_push(&db->db_meta.mt_tbls, tbl);
    return 0;
}

static int db_load_meta(db_t *db, dberr_t *dberr) {
    ASSERT(db->db_offset == 0);
    DEBUG(DBG_TEST, "Reading %lu bytes from offset 0\n", DB_META_SER_BYTES(&db->db_meta));
    int res = db_read(db, &db->db_meta, DB_META_SER_BYTES(&db->db_meta));
    if (res == -1) {
        *dberr = DBERR_ERRNO;
        db_set_lasterr(db, dberr, NULL);
        return res;
    }
    if (db->db_meta.mt_magic != STOR_META_MAGIC) {
        die("Unable to load database (maybe corrupted?): invalid header\n");
    }
    uint16_t nextblkno = 0;
    blkh_t *nextblk = NULL;
    if (db->db_meta.mt_nextblkno > 0) {
        nextblkno = db->db_meta.mt_nextblkno;
        nextblk = db_load_blk(db, nextblkno, true);
        if (nextblk) {
            DEBUG(DBG_TEST, "!!found first nextblk, blkno: %u!!\n", nextblkno);
        }
    }
    if (db->db_meta.mt_num_tables > 0) {
        for (int i = 0; i < db->db_meta.mt_num_tables; i++) {
            blkh_t *blockloadedfrom = NULL;
            DEBUG(DBG_TEST, "db_load_next_table iter %d, db_offset: %ld\n", i, db->db_offset);
            res = db_load_next_table(db, nextblk, &blockloadedfrom);
            if (res == -1) {
                *dberr = DBERR_LOADING_METAINFO;
                db_set_lasterr(db, dberr, NULL);
                return res;
            }
            if (nextblk && blockloadedfrom == nextblk) {
                uint16_t nextblkno = nextblk->bh_nextblkno;
                if (nextblkno > 0) {
                    nextblk = db_load_blk(db, nextblkno, true);
                    DEBUG(DBG_TEST, "!!loaded nextblk, blkno: %u!!\n", nextblkno);
                } else {
                    DEBUG(DBG_TEST, "!!no nextblk found!!\n");
                    nextblk = NULL;
                }
            }
        }
    }
    return 0;
}

int db_open(db_t *db, dberr_t *dberr) {
    ASSERT(db->db_fname);
    //ASSERT(db->db_fd == 0);
    int fd = open(db->db_fname, O_RDWR);
    if (fd == -1) {
        *dberr = DBERR_ERRNO;
        db_set_lasterr(db, dberr, NULL);
        return -1;
    }
    db->db_fd = fd;
    db_seek(db, SEEK_SET, 0);
    int load_res = db_load_meta(db, dberr);
    if (load_res != 0) return load_res;
    ASSERT(db->db_meta.mt_sersize > 0);
    return 0;
}

tbl_t *db_table_from_idx(db_t *db, int idx) {
    ASSERT(idx >= 0 && idx < db->db_meta.mt_tbls.length);
    return db->db_meta.mt_tbls.data[idx];
}

col_t *db_col_from_idx(tbl_t *tbl, int idx) {
    ASSERT(idx < tbl->tbl_num_cols);
    return &tbl->tbl_cols.data[idx];
}

col_t *db_col_from_name(tbl_t *tbl, const char *name, int *colidx) {
    col_t *col;
    int i = 0;
    vec_foreach_ptr(&tbl->tbl_cols, col, i) {
        if (strncmp(col->col_name, name, STOR_COLNAME_MAX) == 0) {
            if (colidx != NULL) {
                *colidx = i;
            }
            return col;
        }
    }
    return NULL;
}

static int db_flush_blk_header(db_t *db, blkh_t *blkh, dberr_t *dberr) {
    off_t saved_offset = db->db_offset;
    int seek_res = db_seek(db, SEEK_SET, blkh->bh_blkno*STOR_PAGESZ);
    if (seek_res != 0) {
        *dberr = DBERR_ERRNO;
        db_set_lasterr(db, dberr, NULL);
        return -1;
    }
    int write_res = db_write(db, blkh, sizeof(*blkh));
    if (write_res == -1) {
        *dberr = DBERR_ERRNO;
        db_set_lasterr(db, dberr, NULL);
        return -1;
    }
    db_seek(db, SEEK_SET, saved_offset);
    return 0;
}

int db_flush_meta(db_t *db, dberr_t *dberr) {
    if (db->db_mem_only) {
        db->db_mt_dirty = false;
        return 0;
    }
    if (db->db_fd <= 0) {
        return -1;
    }
    if (!db->db_mt_dirty) {
        return -1;
    }
    int seek_res, write_res;
    seek_res = db_seek(db, SEEK_SET, 0);
    if (seek_res != 0) {
        *dberr = DBERR_ERRNO;
        db_set_lasterr(db, dberr, NULL);
        return -1;
    }
    ASSERT(db->db_meta.mt_magic == STOR_META_MAGIC);
    size_t meta_bytes = DB_META_SER_BYTES(&db->db_meta);
    size_t blk_bytes_written = 0;
    size_t bytes_written_total = 0;
    int extra_blks_idx = 0;
    int num_extra_blks = db->db_meta.mt_blks.length;
    int extra_blks_needed = 0;
    size_t alltbls_bytes = 0;
    for (int i = 0; i < db->db_meta.mt_num_tables; i++) {
        tbl_t *tbl = db_table_from_idx(db, i);
        ASSERT(tbl);
        size_t fulltbl_bytes = DB_TBL_SER_BYTES_POSTLOAD(tbl);
        alltbls_bytes += fulltbl_bytes;
    }
    size_t meta_bytes_all = meta_bytes + alltbls_bytes;
    extra_blks_needed = meta_bytes_all / STOR_PAGESZ;
    while (num_extra_blks < extra_blks_needed) {
        uint16_t next_blkno = db_next_blkno(db, dberr);
        ASSERT(next_blkno > 0);
        blkh_t *newblk = db_alloc_blk(db, next_blkno, NULL, false, dberr);
        DEBUG(DBG_TEST, "Allocating new block (%u) for metainfo\n", next_blkno);
        ASSERT(newblk);
        if (db->db_meta.mt_blks.length > 0) {
            int k;
            blkh_t *blkp = NULL;
            vec_foreach(&db->db_meta.mt_blks, blkp, k) {
                if (k != db->db_meta.mt_blks.length-1) {
                    ASSERT(blkp->bh_nextblkno > 0);
                }
            }
            blkh_t *lastblk = vec_last(&db->db_meta.mt_blks);
            ASSERT(lastblk->bh_nextblkno == 0);
            lastblk->bh_nextblkno = next_blkno;
            ASSERT(db_flush_blk_header(db, lastblk, dberr) == 0);
        } else {
            ASSERT(db->db_meta.mt_nextblkno == 0);
            db->db_meta.mt_nextblkno = next_blkno;
        }
        vec_push(&db->db_meta.mt_blks, newblk);
        num_extra_blks++;
    }
    seek_res = db_seek(db, SEEK_SET, 0);
    if (seek_res != 0) {
        *dberr = DBERR_ERRNO;
        db_set_lasterr(db, dberr, NULL);
        return -1;
    }
    write_res = db_write(db, &db->db_meta, meta_bytes);
    if (write_res == -1) {
        *dberr = DBERR_ERRNO;
        db_set_lasterr(db, dberr, NULL);
        return -1;
    }
    blk_bytes_written += meta_bytes;
    bytes_written_total += meta_bytes;
    for (int i = 0; i < db->db_meta.mt_num_tables; i++) {
        tbl_t *tbl = db_table_from_idx(db, i);
        ASSERT(tbl);
        size_t fulltbl_sz = DB_TBL_SER_BYTES_POSTLOAD(tbl);
        unsigned char *tblbuf = malloc(fulltbl_sz);
        ASSERT_MEM(tblbuf);
        memcpy(tblbuf, tbl, sizeof(*tbl)); // PRELOAD size
        col_t *curcol;
        int j = 0;
        unsigned char *tblbufp = tblbuf+sizeof(*tbl);
        // copy column info for table
        vec_foreach_ptr(&tbl->tbl_cols, curcol, j) {
            memcpy(tblbufp, curcol, sizeof(*curcol));
            tblbufp += sizeof(*curcol);
        }
        j = 0;
        uint16_t curblk = 0;
        // copy blk numbers for table
        vec_foreach(&tbl->tbl_blknos, curblk, j) {
            ASSERT(curblk > 0);
            memcpy(tblbufp, &curblk, sizeof(curblk));
            tblbufp += sizeof(curblk);
        }
        ASSERT(tblbufp - tblbuf == fulltbl_sz);
        // ex: 1000 written, 3500 fulltbl_sz, 4096 pagesize, we write:
        //   1) 3096 bytes to this block
        //   2) 404 bytes to next block
        //
        if (blk_bytes_written+fulltbl_sz > STOR_PAGESZ) {
            size_t thisblk_write_sz = STOR_PAGESZ-blk_bytes_written;
            size_t nextblk_write_sz = fulltbl_sz - thisblk_write_sz;
            DEBUG(DBG_TEST,
                "i == %d, writing table buffer (%lu bytes) to offset %ld\n", i, thisblk_write_sz, db->db_offset
            );
            write_res = db_write(db, tblbuf, thisblk_write_sz);
            if (write_res == -1) {
                *dberr = DBERR_ERRNO;
                db_set_lasterr(db, dberr, NULL);
                return write_res;
            }
            blk_bytes_written += write_res;
            bytes_written_total += write_res;
            ASSERT(blk_bytes_written % STOR_PAGESZ == 0);
            blk_bytes_written = sizeof(blkh_t);
            uint16_t blkno = db->db_meta.mt_blks.data[extra_blks_idx]->bh_blkno;
            ASSERT(blkno > 0);
            db_seek(db, SEEK_SET, (blkno*STOR_PAGESZ)+sizeof(blkh_t));
            extra_blks_idx++;
            DEBUG(DBG_TEST,
                "i == %d, writing table buffer (%lu bytes) to offset %ld\n", i, nextblk_write_sz, db->db_offset
            );
            write_res = db_write(db, tblbuf+thisblk_write_sz, nextblk_write_sz);
            if (write_res == -1) {
                *dberr = DBERR_ERRNO;
                db_set_lasterr(db, dberr, NULL);
                return write_res;
            }
            blk_bytes_written += write_res;
            bytes_written_total += write_res;
            free(tblbuf);
        } else {
            DEBUG(DBG_TEST,
                "i == %d, writing table buffer (%lu bytes) to offset %ld\n", i, fulltbl_sz, db->db_offset
            );
            write_res = db_write(db, tblbuf, fulltbl_sz);
            free(tblbuf);
            if (write_res == -1) {
                *dberr = DBERR_ERRNO;
                db_set_lasterr(db, dberr, NULL);
                return write_res;
            }
            blk_bytes_written += write_res;
            bytes_written_total += write_res;
        }
    }
    ASSERT(meta_bytes_all == bytes_written_total);
    ASSERT(extra_blks_idx == (db->db_meta.mt_blks.length));
    db->db_meta.mt_sersize = bytes_written_total;
    seek_res = db_seek(db, SEEK_SET, 4);
    if (seek_res != 0) return seek_res;
    write_res = write(db->db_fd, &db->db_meta.mt_sersize, sizeof(size_t));
    // NOTE: db_num_writes not incremented here, it's fine, this is internal
    if (write_res == -1) return write_res;
    seek_res = db_seek(db, SEEK_SET, 0);
    if (seek_res != 0) return seek_res;
    db->db_mt_dirty = false;
    return 0;
}

int db_coltype(db_t *db, char *coltype, qcoltype_t *qtype, dberr_t *dberr) {
    if (strncmp(coltype, "int", 4) == 0) {
        qtype->type = COLTYPE_INT;
        qtype->size = sizeof(int);
    } else if (strncmp(coltype, "char", 5) == 0) {
        qtype->type = COLTYPE_CHAR;
        qtype->size = 1;
    } else if (strncmp(coltype, "varchar", 7) == 0) {
        char *sz_delimstart = strchr(coltype, '(');
        char *sz_delimend = NULL;
        long sz_long;
        if (sz_delimstart) {
            sz_long = strtol(sz_delimstart+1, &sz_delimend, 10);
            if (sz_long < 0 || sz_long == LONG_MAX) {
                *dberr = DBERR_VAL_OUT_OF_RANGE;
                db_set_lasterr(db, dberr, kstrdup("column size out of range"));
                return -1;
            }
            if (sz_delimend == NULL || *sz_delimend != ')') {
                *dberr = DBERR_PARSE_ERR;
                db_set_lasterr(db, dberr, kstrdup("error parsing column size"));
                return -1;
            }
            qtype->type = COLTYPE_VARCHAR;
            qtype->size = (size_t)sz_long;
            DEBUG(DBG_SCHEMA, "Adding VARCHAR type of size %lu\n", qtype->size);
        } else {
            qtype->type = COLTYPE_VARCHAR;
            qtype->size = STOR_VARCHAR_MAX;
        }
    } else if (strncmp(coltype, "double", 7) == 0) {
        qtype->type = COLTYPE_DOUBLE;
        qtype->size = sizeof(double);
    } else {
        *dberr = DBERR_COLTYPE_INVALID;
        db_set_lasterr(db, dberr, kstrndup(coltype, STOR_COLNAME_MAX));
        return -1;
    }
    return 0;
}

const char *coltype_str(qcoltype_t *qtype) {
    switch(qtype->type) {
    case COLTYPE_INT:
        return "int";
    case COLTYPE_CHAR:
        return "char";
    case COLTYPE_VARCHAR:
        return "varchar";
    case COLTYPE_DOUBLE:
        return "double";
    default:
        return "Unknown";
    }
}

int db_add_table(db_t *db, const char *tblname, const char *colinfo, bool flush_to_disk, dberr_t *dberr) {
    if (strnlen(tblname, STOR_TBLNAME_MAX+1) > STOR_TBLNAME_MAX) {
        *dberr = DBERR_TBLNAME_TOO_LONG;
        db_set_lasterr(db, dberr, kstrndup(tblname, STOR_TBLNAME_MAX));
        return -1;
    }
    int num_tbls = db->db_meta.mt_num_tables;
    tblid_t new_id = 1;
    for (int i = 0; i < num_tbls; i++) {
        tbl_t *tbl = db_table_from_idx(db, i);
        ASSERT(tbl->tbl_id > 0);
        if (strncmp(tblname, tbl->tbl_name, STOR_TBLNAME_MAX) == 0) {
            *dberr = DBERR_TBLNAME_EXISTS;
            db_set_lasterr(db, dberr, kstrndup(tblname, STOR_TBLNAME_MAX));
            return -1;
        }
        if (tbl->tbl_id >= new_id) {
            new_id = tbl->tbl_id+1;
        }
    }
    tbl_t *newtbl = malloc(sizeof(*newtbl));
    ASSERT_MEM(newtbl);
    memset(newtbl, 0, sizeof(*newtbl));
    newtbl->tbl_id = new_id;
    strncpy(newtbl->tbl_name, tblname, STOR_TBLNAME_MAX);
    newtbl->tbl_num_cols = 0;
    newtbl->tbl_num_blks = 0;
    vec_init(&newtbl->tbl_cols);
    vec_init(&newtbl->tbl_blknos);

    char *colinfoend = (char*)colinfo + strnlen(colinfo, 1024);
    char *colsep = NULL; // 'col1:type1[,]col2:type2'
    char *coltypesep = NULL; // 'col1[:]type1'
    char *coltypebeg = NULL; // type1
    char *colbeg = (char*)colinfo; // col1
    char *colbegnext = colbeg;
    char colnamebuf[STOR_COLNAME_MAX];
    char coltypebuf[STOR_COLTYPE_MAX];
    int numcols = 0;
    bool err = false;
    do {
        colbeg = colbegnext;
        coltypesep = strchr(colbeg, ':');
        if (!coltypesep) break;
        coltypebeg = coltypesep+1;
        size_t colnamelen = coltypesep - colbeg; // including NULL byte
        if (colnamelen > STOR_COLNAME_MAX) {
            err = true;
            *dberr = DBERR_COLNAME_TOO_LONG;
            db_set_lasterr(db, dberr, kstrndup(colbeg, STOR_COLNAME_MAX));
            break;
        }
        size_t coltypelen = STOR_COLTYPE_MAX;
        colsep = strchr(colbeg, ',');
        if (colsep) {
            colbegnext = colsep+1;
            coltypelen = colsep - coltypebeg;
        } else {
            colbegnext = NULL;
            coltypelen = colinfoend - coltypebeg;
        }

        numcols++;
        col_t newcol;
        memset(&newcol, 0, sizeof(newcol));
        newcol.col_id = (new_id * 1000) + numcols;
        memset(colnamebuf, 0, sizeof(colnamebuf));
        memset(coltypebuf, 0, sizeof(coltypebuf));
        strncpy(colnamebuf, colbeg, colnamelen);
        strncpy(coltypebuf, coltypebeg, coltypelen);
        strncpy(newcol.col_name, colnamebuf, colnamelen);
        DEBUG(DBG_SCHEMA, "Adding column \"%s\" (type:%s)\n", colnamebuf, coltypebuf);
        qcoltype_t qcol_type;
        int coltype_res = db_coltype(db, coltypebuf, &qcol_type, dberr);
        if (coltype_res != 0) {
            LOG_ERR("Invalid column type: %s\n", coltypebuf);
            err = true;
            break;
        }
        newcol.qcol_type = qcol_type;
        newtbl->tbl_num_cols++;
        vec_push(&newtbl->tbl_cols, newcol);
    } while (colbegnext != NULL);

    if (err) {
        vec_deinit(&newtbl->tbl_cols);
        vec_deinit(&newtbl->tbl_blknos);
        free(newtbl);
        return -1;
    }

    vec_push(&db->db_meta.mt_tbls, newtbl);

    db->db_mt_dirty = true;
    db->db_meta.mt_num_tables++;
    if (flush_to_disk) {
        return db_flush_meta(db, dberr);
    } else {
        return 0;
    }
}

// NOTE: assumes the given block is a data block, not a block for meta info
static void db_free_blk(db_t *db, uint16_t cur_blkno) {
    int blkinfo_idx = -1;
    int blkcache_idx = -1;
    int blksdirty_idx = -1;
    bool freed_blk = false;
    blkh_t *curblk = NULL;
    int i;
    vec_foreach(&db->db_blkcache, curblk, i) {
        if (curblk->bh_blkno == cur_blkno) {
            blkcache_idx = i;
            break;
        }
    }
    blkinfo_t *curblkinfo = NULL;
    i = 0;
    vec_foreach_ptr(&db->db_vblkinfo, curblkinfo, i) {
        if (curblkinfo->blk->bh_blkno == cur_blkno) {
            blkinfo_idx = i;
            break;
        }
    }
    i = 0;
    uint16_t curblkno = 0;
    vec_foreach(&db->db_blksdirty, curblkno, i) {
        if (curblkno == cur_blkno) {
            blksdirty_idx = i;
            break;
        }
    }

    if (blksdirty_idx != -1) {
        vec_splice(&db->db_blksdirty, blksdirty_idx, 1);
    }
    if (blkcache_idx != -1) {
        blkh_t *blk_found = db->db_blkcache.data[blkcache_idx];
        ASSERT(blk_found);
        free(blk_found);
        freed_blk = true;
        vec_splice(&db->db_blkcache, blkcache_idx, 1);
    }
    if (blkinfo_idx != -1) {
        if (!freed_blk) {
            free(db->db_vblkinfo.data[blkinfo_idx].blk);
            freed_blk = true;
        }
        vec_splice(&db->db_vblkinfo, blkinfo_idx, 1);
    }
}


int db_clear_blk(db_t *db, uint16_t num, dberr_t *dberr) {
    ASSERT(num > 0);
    off_t saved_offset = db->db_offset;
    int res = db_seek(db, SEEK_SET, num*STOR_PAGESZ);
    if (res != 0) {
        *dberr = DBERR_ERRNO;
        db_set_lasterr(db, dberr, NULL);
        return -1;
    }
    uint16_t tombstone = STOR_BLKH_TOMBSTONE;
    res = db_write(db, &tombstone, sizeof(uint16_t));
    if (res <= 0) {
        *dberr = DBERR_ERRNO;
        db_set_lasterr(db, dberr, NULL);
        return -1;
    }
    res = db_write(db, empty_page, sizeof(empty_page)-sizeof(uint16_t));
    if (res <= 0) {
        *dberr = DBERR_ERRNO;
        db_set_lasterr(db, dberr, NULL);
        return -1;
    }
    db_seek(db, SEEK_SET, saved_offset);
    return 0;
}

int db_drop_table(db_t *db, tbl_t *tbl, bool clear_blks, bool flush_to_disk, dberr_t *dberr) {
    vec_deinit(&tbl->tbl_cols);
    uint16_t cur_blkno = 0;
    int i = 0;
    int clear_res;
    vec_foreach(&tbl->tbl_blknos, cur_blkno, i) {
        if (clear_blks) {
            clear_res = db_clear_blk(db, cur_blkno, dberr);
            db_free_blk(db, cur_blkno);
            if (clear_res != 0) {
                db_log_lasterr(db);
                break; // just stop clearing the blocks
            }
        } else {
            db_free_blk(db, cur_blkno);
        }
    }
    if (clear_blks) {
        vec_deinit(&tbl->tbl_blknos);
    }
    ASSERT(db->db_meta.mt_num_tables > 0);
    db->db_meta.mt_num_tables--;
    db->db_mt_dirty = true;
    tbl_t *curtbl = NULL;
    int mt_tbls_idx = -1;
    i = 0;
    vec_foreach(&db->db_meta.mt_tbls, curtbl, i) {
        if (curtbl->tbl_id == tbl->tbl_id) {
            if (tbl != curtbl) free(curtbl);
            mt_tbls_idx = i;
        }
    }
    ASSERT(mt_tbls_idx >= 0);
    vec_splice(&db->db_meta.mt_tbls, mt_tbls_idx, 1);
    if (flush_to_disk) {
        return db_flush_meta(db, dberr);
    } else {
        return 0;
    }
}

static int db_deserialize_val(db_t *db, char *dbval, qcoltype_t *qtype, dbtval_t *tval, size_t *valsz, dberr_t *dberr) {
    tval->qtype = *qtype;
    switch (qtype->type) {
        case COLTYPE_INT: {
            long val = strtol(dbval, NULL, 10);
            if (val < INT_MIN || val > INT_MAX) {
                DEBUG(DBG_DESER, "int out of range: %s\n", dbval);
                *dberr = DBERR_VAL_OUT_OF_RANGE;
                db_set_lasterr(db, dberr, kstrndup(dbval, 12));
                return -1;
            }
            int ival = (int)val;
            tval->val = (dbval_t)ival;
            if (valsz) {
                *valsz = sizeof(int);
            }
            break;
        }
        case COLTYPE_CHAR: {
            char c = *dbval;
            if (strnlen(dbval, 2) > 1) {
                DEBUG(DBG_DESER, "char out of range: %s\n", dbval);
                *dberr = DBERR_VAL_OUT_OF_RANGE;
                db_set_lasterr(db, dberr, kstrndup(dbval, 10));
                return -1;
            }
            tval->val = (dbval_t)c;
            if (valsz) {
                *valsz = sizeof(char);
            }
            break;
        }
        case COLTYPE_VARCHAR: {
            size_t len = strnlen(dbval, qtype->size+1);
            if (len > qtype->size) {
                *dberr = DBERR_VAL_OUT_OF_RANGE;
                db_set_lasterr(db, dberr, kstrndup(dbval, qtype->size));
                return -1;
            }
            tval->val = (dbval_t)dbval;
            if (valsz) {
                *valsz = len+1;
            }
            break;
        }
        case COLTYPE_DOUBLE: {
            double val = strtod(dbval, NULL);
            if ((val == 0 || val == HUGE_VALF) && errno == ERANGE) {
                *dberr = DBERR_VAL_OUT_OF_RANGE;
                db_set_lasterr(db, dberr, kstrndup(dbval, 12));
                return -1;
            }
            tval->val = (dbval_t)val;
            if (valsz) {
                *valsz = sizeof(double);
            }
            break;
        }
        default:
            ASSERT(0);
            *dberr = DBERR_COLTYPE_INVALID;
            return -1;
    }
    return 0;
}

// Load block from disk (but checks cache first).
blkh_t *db_load_blk(db_t *db, uint16_t num, bool restore_dboffset) {
    int i = 0;
    blkh_t *cachedblk;
    vec_foreach(&db->db_blkcache, cachedblk, i) {
        if (cachedblk->bh_blkno == num) {
            return cachedblk;
        }
    }
    off_t offset = num * STOR_PAGESZ;
    off_t saved_offset = db->db_offset;
    int seek_res = db_seek(db, SEEK_SET, offset);
    if (seek_res != 0) {
        return NULL;
    }
    unsigned char *blk = malloc(STOR_PAGESZ);
    ASSERT_MEM(blk);
    int res = db_read(db, blk, STOR_PAGESZ);
    if (res <= 0) return NULL;
    vec_push(&db->db_blkcache, (blkh_t*)blk);
    blkinfo_t blkinfo;
    vec_init(&blkinfo.blk_holes);
    blkinfo.blk = (blkh_t*)blk;
    blkinfo.is_dirty = false;
    blkinfo.holes_computed = false;
    vec_push(&db->db_vblkinfo, blkinfo);
    if (restore_dboffset) {
        db_seek(db, SEEK_SET, saved_offset);
    }
    return (blkh_t*)blk;
}

// Allocates new data block memory, puts it into cache, and writes it to disk.
// NOTE: Changes offset of db->db_offset.
blkh_t *db_alloc_blk(db_t *db, uint16_t num, tbl_t *tbl, bool allow_overwrite, dberr_t *dberr) {
    off_t offset = num * STOR_PAGESZ;
    int seek_res = db_seek(db, SEEK_SET, offset);
    if (seek_res != 0) {
        *dberr = DBERR_SEEK_ERR;
        db_set_lasterr(db, dberr, NULL);
        return NULL;
    }
    if (!allow_overwrite) {
        blkh_t blkh;
        memset(&blkh, 0, sizeof(blkh));
        off_t last_offset = db->db_offset;
        db_read(db, &blkh, sizeof(blkh));
        if (blkh.bh_magic == STOR_BLKH_MAGIC && blkh.bh_blkno > 0) {
            *dberr = DBERR_INVALID_BLOCK_OVERWRITE;
            db_set_lasterr(db, dberr, NULL);
            return NULL;
        }
        db_seek(db, SEEK_SET, last_offset);
    }
    blkh_t *blk = malloc(STOR_PAGESZ);
    ASSERT_MEM(blk);
    memset(blk, 0, STOR_PAGESZ);
    blk->bh_magic = STOR_BLKH_MAGIC;
    if (tbl) {
        blk->bh_tbl_id = tbl->tbl_id;
        vec_push(&tbl->tbl_blknos, num);
        tbl->tbl_num_blks++;
    }
    blk->bh_blkno = num;
    blk->bh_nextblkno = 0;
    blk->bh_num_records = 0;
    blk->bh_free = STOR_PAGESZ - sizeof(*blk);
    int res = db_write(db, blk, STOR_PAGESZ);
    if (res <= 0) {
        *dberr = DBERR_ERRNO;
        db_set_lasterr(db, dberr, NULL);
        return NULL;
    }
    vec_push(&db->db_blkcache, blk);
    blkinfo_t blkinfo;
    vec_init(&blkinfo.blk_holes);
    blkinfo.blk = blk;
    blkinfo.is_dirty = false;
    blkinfo.holes_computed = true; // FIXME: push 1 large hole
    vec_push(&db->db_vblkinfo, blkinfo);
    db->db_mt_dirty = true;
    return blk;
}

uint16_t db_next_blkno(db_t *db, dberr_t *dberr) {
    uint16_t max_dirty_blk = 0;
    int cur_blkno;
    int i;
    vec_foreach(&db->db_blksdirty, cur_blkno, i) {
        if (cur_blkno > max_dirty_blk) {
            max_dirty_blk = cur_blkno;
        }
    }
    uint16_t next_blkno = 1;
    off_t saved_pos = db->db_offset;
    off_t seek_res = db_seek(db, SEEK_END, 0);
    if (seek_res != 0) {
        *dberr = DBERR_SEEK_ERR;
        db_set_lasterr(db, dberr, kstrdup("SEEK_END error"));
        return 0;
    }
    size_t filesize = (size_t)db->db_offset;
    ASSERT(filesize < STOR_PAGESZ || ((filesize % STOR_PAGESZ) == 0));
    if (filesize < STOR_PAGESZ) {
        next_blkno = 1;
    } else if (filesize <= (STOR_PAGESZ*2)) {
        next_blkno = 2;
    } else {
        blkh_t blkh;
        int res = db_seek(db, SEEK_SET, filesize-STOR_PAGESZ);
        ASSERT(res != -1);
        res = db_read(db, &blkh, sizeof(blkh));
        ASSERT(res != -1);
        if (blkh.bh_magic != STOR_BLKH_MAGIC) {
            DEBUG(DBG_TEST, "blkh.bh_magic: %u, filesize: %lu\n", blkh.bh_magic, filesize);
        }
        ASSERT(blkh.bh_magic == STOR_BLKH_MAGIC);
        ASSERT(blkh.bh_blkno > 0);
        next_blkno = blkh.bh_blkno+1;
    }
    if ((max_dirty_blk+1) > next_blkno) {
        next_blkno = max_dirty_blk+1;
    }
    bool blk_in_use = true;
    int read_res;
    while (blk_in_use) {
        db_seek(db, SEEK_SET, next_blkno*STOR_PAGESZ);
        blkh_t blkh;
        memset(&blkh, 0, sizeof(blkh));
        read_res = db_read(db, &blkh, sizeof(blkh));
        ASSERT(read_res != -1);
        blk_in_use = blkh.bh_magic == STOR_BLKH_MAGIC;
        if (blk_in_use) next_blkno++;
    }
    db_seek(db, SEEK_SET, saved_pos);
    return next_blkno;
}

static int db_flush_blk(db_t *db, blkh_t *blk) {
    ASSERT(blk->bh_blkno > 0);
    int res = db_seek(db, SEEK_SET, blk->bh_blkno * STOR_PAGESZ);
    if (res != 0) return res;
    ssize_t write_res = db_write(db, blk, STOR_PAGESZ);
    if (write_res != STOR_PAGESZ) {
        return -1;
    }
    return 0;
}

int db_flush_dirty_blks(db_t *db) {
    int blkno, i;
    blkh_t *blk;
    vec_foreach(&db->db_blksdirty, blkno, i) {
        int j;
        bool found = false;
        vec_foreach(&db->db_blkcache, blk, j) {
            if ((int)blk->bh_blkno == blkno) {
                db_flush_blk(db, blk);
                found = true;
                break;
            }
        }
        if (!found) {
            return -1;
        }
    }
    vec_deinit(&db->db_blksdirty);
    return 0;
}

static blkh_t *db_find_cached_blk_for_rec(db_t *db, tbl_t *tbl, size_t recsz) {
    int i;
    blkh_t *blk;
    vec_foreach(&db->db_blkcache, blk, i) {
        if (blk->bh_tbl_id == tbl->tbl_id && BLK_FITS_RECSZ(blk, recsz)) {
            return blk;
        }
    }
    return NULL;
}

// FIXME: make smarter! Should have an index of blocks for tables somewhere
blkh_t *db_find_blk_for_rec(db_t *db, tbl_t *tbl, size_t recsz, bool alloc_if_not_found, uint16_t *blk_off, bool *isnewblk) {
    ASSERT(recsz < STOR_PAGESZ); // TODO: implement record fragments across blocks
    blkh_t *found = db_find_cached_blk_for_rec(db, tbl, recsz);
    // FIXME: set *blk_off
    if (found) return found;
    blkh_t *blk = NULL;
    uint16_t num = 1;
    do {
        blk = db_load_blk(db, num, true);
        if (blk == NULL || blk->bh_magic != STOR_BLKH_MAGIC) {
            break;
        }
        if (blk->bh_tbl_id == tbl->tbl_id && BLK_FITS_RECSZ(blk, recsz)) { // FIXME: BLK_FITS_RECSZ needs to look for holes, not just free size
            found = blk;
            break;
        }
        num++;
    } while (found == NULL && blk != NULL);
    if (!found && !alloc_if_not_found) {
        return NULL;
    }
    if (!found) { // alloc
        dberr_t dberr;
        blk = db_alloc_blk(db, num, tbl, false, &dberr);
        ASSERT(blk); // FIXME: check dberr
        if (blk_off != NULL) {
            *blk_off = STOR_PAGESZ-recsz;
        }
        if (isnewblk != NULL) {
            *isnewblk = true;
        }
        return blk;
    } else {
        // FIXME: set *blk_off
        return found;
    }
}

// FIXME: bh_free doesn't necessarily mean block fits record, have to look at holes
static bool db_blk_fits_rec(blkh_t *blkh, rec_t *rec) {
    size_t recsz = REC_SZ(rec);
    return BLK_FITS_RECSZ(blkh, recsz);
}

static void db_mark_blk_dirty(db_t *db, blkh_t *blk) {
    int idx = 0;
    vec_find(&db->db_blksdirty, (int)blk->bh_blkno, idx);
    if (idx == -1) {
        vec_push(&db->db_blksdirty, (int)blk->bh_blkno);
    }
}

// Add a record to the in-memory representation of a data block. Caller must
// check that there's room before calling.
int db_blk_cpy_rec(db_t *db, blkh_t *blk, rec_t *rec, uint16_t blk_off, rec_t **recout) {
    ASSERT(!REC_IS_TOMBSTONED(rec));
    ASSERT(!BLK_CONTAINS_REC(blk, rec));
    size_t recsz_total = REC_SZ(rec);
    ASSERT(db_blk_fits_rec(blk, rec));
    char *cpystart = NULL;
    off_t rec_offset;

    if (blk_off > 0) {
        rec_offset = blk_off;
    } else { // FIXME: should always pass blk_off
        if (blk->bh_num_records == 0) {
            rec_offset = STOR_PAGESZ - recsz_total;
        } else {
            rec_offset = PTR(BLK_LAST_REC(blk)) - PTR(blk);
            rec_offset -= recsz_total;
        }
    }
    ASSERT(rec_offset > sizeof(blkh_t) && rec_offset < STOR_PAGESZ);
    DEBUG(DBG_ADD, "Copying record (%lu bytes) at offset: %ld\n", recsz_total, rec_offset);
    DEBUG(DBG_ADD, "Copying record, blkh ptr: %p\n", blk);
    DEBUG(DBG_ADD, "Copying record, blkh ptr+offset: %p\n", PTR(blk)+rec_offset);
    cpystart = PTR(blk)+rec_offset;
    memcpy(cpystart, rec, recsz_total);
    blk_mark_hole_filled(db, blk, NULL, rec_offset, rec_offset+recsz_total);
    blk->bh_free -= (recsz_total + sizeof(uint16_t));
    blk->bh_record_offsets[blk->bh_num_records] = rec_offset;
    blk->bh_num_records++;
    db_mark_blk_dirty(db, blk);
    if (recout != NULL) {
        *recout = (rec_t*)cpystart;
    }
    return 0;
}

static int REC_BLK_IDX(rec_t *rec, blkh_t *blk) {
    for (int i = 0; i < blk->bh_num_records; i++) {
        if (PTR(blk)+blk->bh_record_offsets[i] == PTR(rec)) {
            return i;
        }
    }
    return -1;
}

static uint16_t REC_BLK_OFFSET(rec_t *rec, blkh_t *blk) {
    ptrdiff_t offset = PTR(rec)-PTR(blk);
    ASSERT(offset > 0 && offset < STOR_PAGESZ);
    return (uint16_t)offset;
}

// Remove a record from the in-memory representation of a data block.
static int db_blk_rm_rec(db_t *db, blkh_t *blk, rec_t *rec) {
    ASSERT(BLK_CONTAINS_REC(blk, rec));
    ASSERT(blk->bh_num_records > 0);
    int recidx = REC_BLK_IDX(rec, blk);
    ASSERT(recidx != -1);
    int old_num_recs = (int)blk->bh_num_records;
    blk->bh_num_records--;
    size_t rec_sz = REC_SZ(rec);
    blk->bh_free += (rec_sz+sizeof(uint16_t));
    memset(rec, 0, rec_sz);
    size_t tombstone_val = REC_H_TOMBSTONE_VALUE;
    memcpy(rec, &tombstone_val, sizeof(size_t));
    // Update the record offsets in the block header.
    // Example: deleting recidx = 1, old_num_recs = 10
    //   memmove(PTR+1, PTR+2, (10-2)*sizeof(uint16_t))
    if (recidx != (old_num_recs-1)) {
        memmove(blk->bh_record_offsets+recidx,
                blk->bh_record_offsets+recidx+1,
                ((old_num_recs-(recidx+1))*sizeof(uint16_t))
               );
    }
    uint16_t rec_offset = REC_BLK_OFFSET(rec, blk);
    blk_mark_new_hole(db, blk, NULL, rec_offset, rec_offset+rec_sz);
    db_mark_blk_dirty(db, blk);
    return 0;
}

rec_t *BLK_NTH_REC(blkh_t *blk, int n) {
    if (blk->bh_num_records <= n) {
        return NULL;
    } else {
        return (rec_t*)(PTR(blk)+blk->bh_record_offsets[n]);
    }
}
// returns latest record entered into block
rec_t *BLK_LAST_REC(blkh_t *blk) {
    return BLK_NTH_REC(blk, blk->bh_num_records-1);
}
// returns first record entered into block
rec_t *BLK_FIRST_REC(blkh_t *blk) {
    return BLK_NTH_REC(blk, 0);
}

// NOTE: after success, the record can be accessed by BLK_LAST_REC(blkh_out)
int db_add_record(db_t *db, const char *tblname, const char *rowvals, blkh_t **blkh_out, bool flushblk, dberr_t *dberr) {
    const char *valsep = ",";
    tbl_t *tbl = NULL;
    tbl = db_table_from_name(db, tblname);
    if (!tbl) {
        *dberr = DBERR_TBLNAME_NOEXIST;
        db_set_lasterr(db, dberr, kstrndup(tblname, STOR_TBLNAME_MAX));
        return -1;
    }
    ASSERT(tbl->tbl_num_cols > 0);
    char *tok = NULL;
    // strtok() doesn't work with string literals (modifies string)
    char *rowvals_dup = kstrndup(rowvals, STOR_PAGESZ*2);
    char *in = rowvals_dup;
    size_t val_sizes[tbl->tbl_num_cols];
    dbtval_t vals[tbl->tbl_num_cols];
    size_t recsz_total = 0;
    int validx = 0;
    while ((tok = strtok(in, valsep)) != NULL) {
        col_t *col = db_col_from_idx(tbl, validx);
        if (!col) {
            *dberr = DBERR_TOO_MANY_REC_VALUES;
            db_set_lasterr(db, dberr, kstrndup(tok, 100));
            free(rowvals_dup);
            return -1;
        }
        dbtval_t tval;
        dberr_t deser_err;
        size_t valsz = 0;
        int res = db_deserialize_val(db, tok, &col->qcol_type, &tval, &valsz, &deser_err);
        if (res == -1) {
            *dberr = deser_err;
            free(rowvals_dup);
            return -1;
        }
        ASSERT(valsz > 0);
        val_sizes[validx] = valsz;
        vals[validx] = tval;
        recsz_total += valsz;
        validx++;
        in = NULL;
    }
    size_t rech_sz = sizeof(rech_t)+sizeof(off_t)*tbl->tbl_num_cols;
    rech_t *rech = malloc(rech_sz);
    ASSERT_MEM(rech);
    memset(rech, 0, rech_sz);
    rech->rech_sz = rech_sz;
    rech->rec_sz = recsz_total;
    off_t *rec_offsets = rech->rec_offsets;
    off_t rec_off = 0;
    for (int i = 0; i < tbl->tbl_num_cols; i++) {
        DEBUG(DBG_ADD, "Saving record value offset: %ld for colidx %d\n", rec_off, i);
        rec_offsets[i] = rec_off;
        rec_off += val_sizes[i];
    }
    size_t recsz_all = rech_sz+rech->rec_sz;
    rec_t *rec = malloc(recsz_all);
    ASSERT_MEM(rec);
    memset(rec, 0, recsz_all);
    memcpy(rec, rech, rech_sz);
    ASSERT(rec->header.rech_sz == rech->rech_sz);
    ASSERT(rec->header.rec_sz == rech->rec_sz);
    free(rech);
    char *rec_vals = REC_VALUES_PTR(rec);
    for (int i = 0; i < tbl->tbl_num_cols; i++) {
        ASSERT(val_sizes[i] > 0);
        switch (vals[i].qtype.type) {
            case COLTYPE_VARCHAR:
                DEBUG(DBG_ADD, "Copying string %s (%ld bytes) to record\n", vals[i].val.sval, val_sizes[i]);
                memcpy(rec_vals, vals[i].val.sval, val_sizes[i]);
                break;
            case COLTYPE_INT:
                DEBUG(DBG_ADD, "Copying int %d to record\n", vals[i].val.ival);
                ASSERT(val_sizes[i] == sizeof(int));
                memcpy(rec_vals, &(vals[i].val.ival), val_sizes[i]);
                break;
            default:
                memcpy(rec_vals, &vals[i].val, val_sizes[i]);
                break;
        }
        rec_vals += val_sizes[i];
    }
    bool isnewblk = false;
    blkh_t *blkh = db_find_blk_for_rec(db, tbl, recsz_all, true, NULL, &isnewblk);
    ASSERT(blkh);
    int add_res = db_blk_cpy_rec(db, blkh, rec, 0, NULL);
    if (add_res != 0) return add_res;
    if (blkh_out != NULL) {
        *blkh_out = blkh;
    }
    if (flushblk) {
        DEBUG(DBG_ADD, "flushing blk for new record\n");
        db_flush_blk(db, blkh);
    } else {
        db_mark_blk_dirty(db, blkh);
    }
    db->db_mt_dirty = isnewblk;
    return 0;
}

static bool record_val_matches(dbtval_t *recval, dbsrchcrit_t *srchcrit) {
    ASSERT(recval->qtype.type == srchcrit->qtype.type && recval->qtype.type > COLTYPE_ERR);
    switch(recval->qtype.type) {
        case COLTYPE_INT:
            DEBUG(DBG_SRCH, "FIND [INT] => recval: %d, srchcrit: %d\n", recval->val.ival, srchcrit->val.ival);
            return recval->val.ival == srchcrit->val.ival;
        case COLTYPE_CHAR:
            DEBUG(DBG_SRCH, "FIND [CHAR] => recval: %c, srchcrit: %c\n", recval->val.cval, srchcrit->val.cval);
            return recval->val.cval == srchcrit->val.cval;
        case COLTYPE_VARCHAR:
            DEBUG(DBG_SRCH, "FIND [VARCHAR] => recval: %s, srchcrit: %s\n", recval->val.sval, srchcrit->val.sval);
            return strncmp(recval->val.sval, srchcrit->val.sval, recval->qtype.size) == 0;
        case COLTYPE_DOUBLE:
            DEBUG(DBG_SRCH, "FIND [DOUBLE] => recval: %f, srchcrit: %f\n", recval->val.dval, srchcrit->val.dval);
            return recval->val.dval == srchcrit->val.dval;
        default:
            die("unreachable\n");
            return false;
    }
}

dbval_t REC_DBVAL(rec_t *rec, int colidx, coltype_t type) {
    if (type == COLTYPE_VARCHAR) {
        return (dbval_t)REC_VALUE_PTR(rec, colidx);
    } else {
        return *(dbval_t*)REC_VALUE_PTR(rec, colidx);
    }
}

void *DBVAL_PTR(dbval_t *dbval, coltype_t type) {
    switch(type) {
        case COLTYPE_VARCHAR:
            return dbval->sval;
        case COLTYPE_CHAR:
            return &dbval->cval;
        case COLTYPE_DOUBLE:
            return &dbval->dval;
        case COLTYPE_INT:
            return &dbval->ival;
        default:
            return NULL;
    }
}

static bool db_record_matches(rec_t *rec, vec_dbsrchcrit_t *vsearch_crit) {
    dbsrchcrit_t *search_crit;
    int idx;
    vec_foreach_ptr(vsearch_crit, search_crit, idx) {
        off_t offset = rec->header.rec_offsets[search_crit->col_idx];
        if (search_crit->col_idx > 0) {
            ASSERT(offset > 0);
        } else if (search_crit->col_idx == 0) {
            ASSERT(offset == 0);
        }
        dbtval_t tval;
        tval.qtype = search_crit->qtype;
        dbval_t val;
        DEBUG(DBG_SRCH, "record value offset for col idx %d: %ld\n",
            search_crit->col_idx, offset
        );
        val = REC_DBVAL(rec, search_crit->col_idx, tval.qtype.type);
        tval.val = val;
        /*if (tval.type == COLTYPE_INT) {*/
            /*DEBUG(DBG_SRCH, "record value for int: %d\n", tval.val.ival);*/
        /*}*/
        /*if (tval.type == COLTYPE_VARCHAR) {*/
            /*DEBUG(DBG_SRCH, "record value for string: %s\n", tval.val.sval);*/
        /*}*/
        if (!record_val_matches(&tval, search_crit)) {
            return false;
        }
    }
    return true;
}

static int sort_by_colidx_fn(const void *val1, const void *val2) {
    if (((dbsrchcrit_t*)val1)->col_idx < ((dbsrchcrit_t*)val2)->col_idx) {
        return -1;
    } else {
        return 1;
    }
}

static void db_sort_srchcrit(tbl_t *tbl, vec_dbsrchcrit_t *vsearch_crit) {
    (void)tbl;
    vec_sort(vsearch_crit, sort_by_colidx_fn);
}

int db_parse_srchcrit(db_t *db, tbl_t *tbl, const char *srchcrit_str, vec_dbsrchcrit_t *vsearch_crit, dberr_t *dberr) {
    const char *colvalsep = "=";
    const char *valcolsep = ","; // FIXME: allow ',' in varchar values!
    char *tok = NULL;
    // strtok() doesn't work with string literals (modifies string)
    char *srchcrit_strdup = kstrndup(srchcrit_str, 1024);
    char *in = srchcrit_strdup;
    int idx = 0;
    int colidx = -1;
    col_t *col = NULL;
    while ((tok = strtok(in, idx % 2 == 0 ? colvalsep : valcolsep)) != NULL) {
        // parse column name
        if (idx % 2 == 0) {
            col = db_col_from_name(tbl, tok, &colidx);
            if (!col) {
                *dberr = DBERR_COLNAME_NOEXIST;
                db_set_lasterr(db, dberr, kstrndup(tok, STOR_COLNAME_MAX));
                return -1;
            }
        // parse record value
        } else {
            dbtval_t tval;
            dberr_t deser_err;
            int res = db_deserialize_val(db, tok, &col->qcol_type, &tval, NULL, &deser_err);
            if (res == -1) {
                *dberr = deser_err;
                return -1;
            }
            dbsrchcrit_t srchcrit;
            srchcrit.tbl_id = tbl->tbl_id;
            srchcrit.col_id = col->col_id;
            srchcrit.col_idx = colidx;
            srchcrit.val = tval.val;
            srchcrit.qtype = tval.qtype;
            vec_push(vsearch_crit, srchcrit);
        }
        idx++;
        in = NULL;
    }

    // "col1=val1,col2=", we're missing a value
    if (idx % 2 != 0) {
        *dberr = DBERR_MISSING_FIND_VALUE;
        db_set_lasterr(db, dberr, kstrndup(col->col_name, STOR_COLNAME_MAX));
        return -1;
    }

    db_sort_srchcrit(tbl, vsearch_crit);
    return 0;
}

tbl_t *db_table_from_name(db_t *db, const char *tblname) {
    tbl_t *curtbl = NULL;
    int i = 0;
    vec_foreach(&db->db_meta.mt_tbls, curtbl, i) {
        if (strncmp(curtbl->tbl_name, tblname, STOR_TBLNAME_MAX) == 0) {
            return curtbl;
        }
    }
    return NULL;
}

tbl_t *db_table_from_id(db_t *db, tblid_t tblid) {
    tbl_t *curtbl = NULL;
    int i = 0;
    vec_foreach(&db->db_meta.mt_tbls, curtbl, i) {
        if (curtbl->tbl_id == tblid) {
            return curtbl;
        }
    }
    return NULL;
}

int db_find_records(db_t *db, tbl_t *tbl, vec_dbsrchcrit_t *vsearch_crit, srchopt_t *options, vec_recinfo_t *vrecinfo_out, dberr_t *dberr) {
    ASSERT(vsearch_crit->length > 0);
    // go over blocks and try to find record that matches qualifiers, 1 record at a time... (naive)
    uint16_t blkno;
    int blkidx = 0;
    blkh_t *blk;
    vec_foreach(&tbl->tbl_blknos, blkno, blkidx) {
        blk = db_load_blk(db, blkno, true);
        ASSERT(blk);
        if (blk->bh_num_records == 0) {
            continue;
        }
        rec_t *rec;
        int recidx = 0;
        int num_found = 0;
        BLK_RECORDS_FOREACH(blk, rec, recidx) {
            ASSERT(!REC_IS_TOMBSTONED(rec));
            DEBUG(DBG_SRCH, "Record %d\n", recidx);
            DEBUG(DBG_SRCH, "  Block record offset: %u\n", blk->bh_record_offsets[recidx]);
            DEBUG(DBG_SRCH, "  Record found, rech_sz=%lu\n", rec->header.rech_sz);
            DEBUG(DBG_SRCH, "  Record found, rec_sz=%lu\n", rec->header.rec_sz);
            /*DEBUG(DBG_SRCH, "  Record found, offset[0]=%ld\n", rec->header.rec_offsets[0]);*/
            /*DEBUG(DBG_SRCH, "  Record found, offset[1]=%ld\n", rec->header.rec_offsets[1]);*/
            if (db_record_matches(rec, vsearch_crit)) {
                recinfo_t recinfo;
                recinfo.blk = blk;
                recinfo.rec = rec;
                vec_push(vrecinfo_out, recinfo);
                num_found++;
                if (options->limit && options->limit == num_found) {
                    return 0;
                }
            }
        }
    }
    return 0;
}

size_t DBVAL_SZ(dbval_t *val, qcoltype_t *qtype) {
    switch(qtype->type) {
        case COLTYPE_INT:
            return sizeof(int);
        case COLTYPE_DOUBLE:
            return sizeof(double);
        case COLTYPE_CHAR:
            return 1;
        case COLTYPE_VARCHAR:
            ASSERT(val->sval);
            return strnlen(val->sval, qtype->size-1)+1;
        default:
            LOG_ERR("invalid type for dbval: %s\n", coltype_str(qtype));
            return 0;
    }
}


/*static void db_unmark_blk_dirty(db_t *db, blkh_t *blk) {*/
    /*vec_remove(&db->db_blksdirty, (int)blk->bh_blkno);*/
/*}*/

// Move record from old block to new block, tombstoning the space in the old block. There must be room in
// newblk for the record, so the caller must check for this.
int db_move_record_to_blk(db_t *db, rec_t *rec, blkh_t *oldblk, blkh_t *newblk, uint16_t newrec_blkoff, rec_t **recout, dberr_t *dberr) {
    ASSERT(oldblk->bh_tbl_id == newblk->bh_tbl_id);
    ASSERT(BLK_CONTAINS_REC(oldblk, rec));
    ASSERT(oldblk != newblk);
    ASSERT(db_blk_fits_rec(newblk, rec));
    rec_t *new_rec = NULL;
    size_t rec_sz = REC_SZ(rec);
    int res = db_blk_cpy_rec(db, newblk, rec, newrec_blkoff, &new_rec);
    if (res != 0) {
        // FIXME: set dberr
        ASSERT(0);
        (void)dberr;
        return res;
    }
    ASSERT(new_rec);
    DEBUG(DBG_UPDATE, "old recsz: %lu, new_rec sz: %lu\n", rec_sz, REC_SZ(new_rec));
    ASSERT(rec_sz == REC_SZ(new_rec));
    ASSERT(BLK_CONTAINS_REC(newblk, new_rec));
    res = db_blk_rm_rec(db, oldblk, rec);
    ASSERT(REC_IS_TOMBSTONED(rec));
    ASSERT(!REC_IS_TOMBSTONED(new_rec));
    ASSERT(BLK_CONTAINS_REC(newblk, new_rec));
    if (res != 0) {
        return res;
    }
    if (recout != NULL) {
        *recout = new_rec;
    }
    return 0;
}

static int sort_by_blkdata_offset_fn(const void *val1, const void *val2) {
    if (((blkdata_t*)val1)->blkoff < ((blkdata_t*)val2)->blkoff) {
        return -1;
    } else {
        return 1;
    }
}

static bool interval_overlaps_blkdata(blkh_t *blk, blkdata_t *blkdata, uint16_t data_start, uint16_t data_end) {
    ASSERT(blkdata->blk == blk);
    ASSERT(data_end > data_start);
    if (data_start < blkdata->blkoff) {
        return data_end > blkdata->blkoff;
    } else if (data_start > blkdata->blkoff) {
        return data_start < blkdata->blkoff+blkdata->datasz;
    } else {
        return true;
    }
}

blkinfo_t *db_blkinfo(db_t *db, blkh_t *blk) {
    blkinfo_t *blkinfo_p = NULL;
    int i;
    vec_foreach_ptr(&db->db_vblkinfo, blkinfo_p, i) {
        ASSERT(blkinfo_p->blk);
        if (blkinfo_p->blk->bh_blkno == blk->bh_blkno) {
            return blkinfo_p;
        }
    }
    return NULL;
}

// Mark a hole as filled.
// Example:
//   Current block holes [off_start,off_end]: (100,150), (200,100)
//   Mark filled [off_start,off_end]: (110,140)
//   This area overlaps a hole and doesn't start or end at its boundaries, so
//   we need to create a new hole.
//   After the update we should have: (100,109), (141,150), (200,100)
void blk_mark_hole_filled(db_t *db, blkh_t *blk, vec_blkdata_t *vholes, uint16_t fill_start, uint16_t fill_end) {
    ASSERT(blk);
    ASSERT(fill_end > fill_start);
    uint16_t fillsz = fill_end-fill_start;
    blkinfo_t *blkinfo_p = db_blkinfo(db, blk);
    int i;
    if (vholes == NULL) {
        if (!blkinfo_p->holes_computed) {
            blk_find_holes(db, blk, &blkinfo_p->blk_holes, true);
        }
        vholes = &blkinfo_p->blk_holes;
    }
    blkdata_t *hole;
    i = 0;
    int holeidx_del = -1;
    /*int holeidx_new = -1;*/
    vec_blkdata_t vadded_holes;
    vec_init(&vadded_holes);
    vec_foreach_ptr(vholes, hole, i) {
        if (interval_overlaps_blkdata(blk, hole, fill_start, fill_end)) {
            if (hole->blkoff == fill_start && hole->datasz == fillsz) {
                holeidx_del = i;
                break;
            //
            } else if (hole->blkoff == fill_start) { // hole filled at top of hole
                hole->blkoff = fill_end+1;
                hole->datasz -= (fillsz+1);
                ASSERT(hole->datasz > 0);
            } else if (fill_end == hole->blkoff+hole->datasz) { // hole filled at bottom of hole
                hole->datasz -= (fillsz+1);
            } else { // hole filled somewhere within the hole
                // split hole in middle
                ASSERT(fill_start > 0);
                uint16_t hole_end1 = fill_start-1;
                ASSERT(hole_end1 > hole->blkoff);
                uint16_t hole_datasz_old = hole->datasz;
                hole->datasz = hole_end1-hole->blkoff;
                blkdata_t newhole;
                newhole.blk = blk;
                newhole.blkoff = fill_end+1;
                uint16_t hole_end2 = hole->blkoff+hole_datasz_old;
                ASSERT(hole_end2 > newhole.blkoff);
                /*holeidx_new = i+1;*/
                newhole.datasz = hole_end2-newhole.blkoff;
                vec_push(&vadded_holes, newhole);
            }
        }
    }
    if (holeidx_del != -1) {
        vec_splice(vholes, holeidx_del, 1);
    } else if (vadded_holes.length > 0) {
        ASSERT(vadded_holes.length == 1);
        /*ASSERT(holeidx_new >= 0);*/
        vec_push(vholes, vadded_holes.data[0]);
        vec_deinit(&vadded_holes);
    }
}
void blk_mark_new_hole(db_t *db, blkh_t *blk, vec_blkdata_t *vholes, uint16_t hole_start, uint16_t hole_end) {
    ASSERT(hole_end > hole_start);
    ASSERT(hole_end <= STOR_PAGESZ);
    blkinfo_t *blkinfo_p;
    blkinfo_t *blkinfo_pfound = NULL;
    int i;
    if (vholes == NULL) {
        vec_foreach_ptr(&db->db_vblkinfo, blkinfo_p, i) {
            if (blkinfo_p->blk == blk) {
                blkinfo_pfound = blkinfo_p;
                break;
            }
        }
        ASSERT(blkinfo_pfound);
        if (!blkinfo_pfound->holes_computed) {
            return;
        }
        vholes = &blkinfo_pfound->blk_holes;
    }
    blkdata_t hole;
    hole.blk = blk;
    hole.blkoff = hole_start;
    hole.datasz = hole_end-hole_start;
    vec_push(vholes, hole);
}

// Find holes in the block. Add them to *vholes argument and
// cache it in db->db_vblkinfo[n]->blk_holes.
// Heuristic:
// 1) Iterate over the records, saving their offset and size in arrays
// ex: [10,40],[100,150] (2 records found, one near the top of the block (40 bytes),
// the next further down at offset 100 (150 bytes).
// 2) Sort the arrays by their offset (first element in the arrays)
// 3) Iterate over the sorted arrays to find the holes
// Holes= (0,9),(41,99),(151,END)
void blk_find_holes(db_t *db, blkh_t *blk, vec_blkdata_t *vholes, bool force_recompute) {
    uint16_t blkoff_beg = BLKH_SIZE(blk);
    blkinfo_t *blkinfo_p;
    blkinfo_t *blkinfo_pfound = NULL;
    int i = 0;
    vec_foreach_ptr(&db->db_vblkinfo, blkinfo_p, i) {
        if (blkinfo_p->blk->bh_blkno == blk->bh_blkno) {
            blkinfo_pfound = blkinfo_p;
            break;
        }
    }
    ASSERT(blkinfo_pfound);
    // if cached, just return them
    if (blkinfo_pfound->holes_computed && !force_recompute) {
        blkdata_t *cached_hole;
        i = 0;
        vec_foreach_ptr(&blkinfo_pfound->blk_holes, cached_hole, i) {
            vec_push(vholes, *cached_hole);
        }
        return;
    }

    vec_blkdata_t vdata; // data in block
    vec_init(&vdata);
    if (blk->bh_num_records == 0) { // 1 big hole
        blkdata_t hole;
        hole.blk = blk;
        hole.blkoff = blkoff_beg+2;
        hole.datasz = STOR_PAGESZ-hole.blkoff;
        vec_push(vholes, hole);
        if (vholes != &blkinfo_pfound->blk_holes) {
            vec_push(&blkinfo_pfound->blk_holes, hole);
        }
        blkinfo_pfound->holes_computed = true;
        return;
    }
    vec_reserve(&vdata, blk->bh_num_records);
    rec_t *rec;
    i = 0;
    BLK_RECORDS_FOREACH(blk, rec, i) {
        blkdata_t recdata;
        recdata.blk = blk;
        recdata.blkoff = REC_BLK_OFFSET(rec, blk);
        recdata.datasz = REC_SZ(rec);
        DEBUG(DBG_TEST, "rec found: (blkoff: %u, datasz: %u)\n", recdata.blkoff, recdata.datasz);
        vec_push(&vdata, recdata);
    }
    vec_sort(&vdata, sort_by_blkdata_offset_fn);
    blkdata_t *recdata_p;
    i = 0;
    uint16_t last_offset = blkoff_beg;
    vec_foreach_ptr(&vdata, recdata_p, i) {
        if (recdata_p->blkoff > last_offset) { // found a hole
            blkdata_t hole;
            hole.blk = blk;
            hole.blkoff = last_offset;
            hole.datasz = recdata_p->blkoff - last_offset;
            last_offset = recdata_p->blkoff+recdata_p->datasz;
            DEBUG(DBG_TEST, "hole found: (blkoff: %u, datasz: %u)\n", hole.blkoff, hole.datasz);
            vec_push(vholes, hole);
            if (vholes != &blkinfo_pfound->blk_holes) {
                vec_push(&blkinfo_pfound->blk_holes, hole);
            }
            blkinfo_pfound->holes_computed = true;
        } else {
            last_offset = recdata_p->blkoff+recdata_p->datasz;
        }
    }
    if (last_offset < STOR_PAGESZ) {
        blkdata_t hole;
        hole.blk = blk;
        hole.blkoff = last_offset;
        hole.datasz = STOR_PAGESZ-last_offset;
        DEBUG(DBG_TEST, "hole found: (blkoff: %u, datasz: %u)\n", hole.blkoff, hole.datasz);
        vec_push(vholes, hole);
        if (vholes != &blkinfo_pfound->blk_holes) {
            vec_push(&blkinfo_pfound->blk_holes, hole);
        }

    }
    vec_deinit(&vdata);
}

// Heuristic:
// There's sufficient space directly below our record if there's a hole that begins right below the record
// and is big enough to contain the new space. NOTE: the passed in vholes are sorted by their block offsets.
static bool blk_has_space_directly_below_record(blkh_t *blk, rec_t *rec, size_t new_space, vec_blkdata_t *vholes) {
    size_t rec_off = REC_BLK_OFFSET(rec, blk);
    ASSERT(rec_off < STOR_PAGESZ && rec_off > 0);
    uint16_t rec_btm_off = (uint16_t)rec_off+(uint16_t)REC_SZ(rec);
    blkdata_t *holep;
    int i;
    DEBUG(DBG_UPDATE, "Trying to find hole directly below record (size needed: %lu) "\
            "(record offset: %u, bottom offset: %u)\n",
            new_space, (uint16_t)rec_off, rec_btm_off);
    vec_foreach_ptr(vholes, holep, i) {
        DEBUG(DBG_UPDATE, "  hole blkoff: %u, size: %u\n", holep->blkoff, holep->datasz);
        if (holep->blkoff == rec_btm_off && holep->datasz >= new_space) {
            DEBUG(DBG_UPDATE, "  FOUND hole (below rec)\n");
            return true;
        }
    }
    return false;
}

// Heuristic:
// There's sufficient space directly above our record if there's a hole that begins above the record, ends 1 byte above the start
// of the record, and is big enough to contain the new space. NOTE: the passed in vholes are sorted by their block offsets.
static bool blk_has_space_directly_above_record(blkh_t *blk, rec_t *rec, size_t new_space, vec_blkdata_t *vholes) {
    size_t rec_off = PTR(rec)-PTR(blk);
    ASSERT(rec_off < STOR_PAGESZ && rec_off > 0);
    blkdata_t *holep;
    int i;
    DEBUG(DBG_UPDATE, "Trying to find hole above record (record offset: %lu)\n", rec_off);
    vec_foreach_ptr(vholes, holep, i) {
        DEBUG(DBG_UPDATE, "  hole blkoff: %u, size: %u\n", holep->blkoff, holep->datasz);
        if (holep->blkoff < rec_off) {
            uint16_t hole_end = holep->blkoff+holep->datasz;
            if (hole_end == (uint16_t)rec_off && holep->datasz >= new_space) {
                DEBUG(DBG_UPDATE, "  FOUND hole (above rec)\n");
                return true;
            }
        }
    }
    return false;
}

// Find a hole anywhere in the block for `rec_sz`.
// TODO: take into account data fragmentation
static blkdata_t *blk_find_hole_for_record(blkh_t *blk, size_t rec_sz, vec_blkdata_t *vholes) {
    blkdata_t *hole;
    int i;
    vec_foreach_ptr(vholes, hole, i) {
        if (hole->datasz >= rec_sz) {
            return hole;
        }
    }
    return NULL;
}

// Grow record within block, with update_info given for new value. Depending on value of
// rec_newstart, record can:
// 1) Grow down, if rec_newstart == rec (space must be available)
// 1) Move up and grow down, if rec_newstart < rec (space must be available)
// 1) Down up and grow down, if rec_newstart > rec (space must be available)
void db_grow_record_within_blk(blkh_t *blk, rec_t *rec, col_t *col, void *rec_newstart, dbsrchcrit_t *update_info, size_t diffsz) {
    size_t recsz = REC_SZ(rec);
    ASSERT(diffsz > 0 && diffsz < (STOR_PAGESZ - recsz));
    char *rec_oldstart = PTR(rec);
    char *valptr = REC_VALUE_PTR(rec, update_info->col_idx);
    char *rec_oldval_start = valptr;
    size_t rec_start_to_val_sz = rec_oldval_start-rec_oldstart;
    char *rec_newval_start = rec_newstart+rec_start_to_val_sz;
   // dbval_t curval = REC_DBVAL(rec, update_info->col_idx, update_info->type);
    //size_t cursz = DBVAL_SZ(&curval, update_info->type);
    size_t newsz = DBVAL_SZ(&update_info->val, &update_info->qtype);
    size_t cursz = newsz-diffsz;
    ASSERT(newsz > cursz);
    DEBUG(DBG_UPDATE, "newsz: %lu, cursz: %lu, diffsz: %lu\n", newsz, cursz, diffsz);
    ASSERT((newsz - cursz) == diffsz);
    char *rec_newval_end = rec_newval_start+newsz;
    char *rec_oldval_end = valptr+cursz;
    char *rec_old_end = rec_oldstart+recsz;
    char *rec_new_end = rec_newstart+(recsz+diffsz);
    uint16_t new_blk_offset = PTR(rec_newstart)-PTR(blk);
    uint16_t old_blk_offset = PTR(rec_oldstart)-PTR(blk);
    if (rec_newstart != rec_oldstart) {
        DEBUG(DBG_UPDATE, "Updating record start, moved from old blkoff (%u) to (%u)\n",
                old_blk_offset, new_blk_offset);
        memcpy(rec_newstart, rec_oldstart, rec_start_to_val_sz);
    } else {
        ASSERT(rec_newval_start == rec_oldval_start);
        ASSERT(rec_newval_end != rec_oldval_end);
        ASSERT(rec_new_end != rec_old_end);
    }
    DEBUG(DBG_UPDATE, "Updating record column: %s (%s) (idx:%d), cursz: %lu, newsz: %lu\n",
            col->col_name, coltype_str(&col->qcol_type), update_info->col_idx, cursz, newsz);
    memcpy(rec_newval_start, DBVAL_PTR(&update_info->val, update_info->qtype.type), newsz);
    if (rec_newval_start+newsz != rec_newval_end) {
        memcpy(rec_newval_end, rec_oldval_end, rec_old_end-rec_oldval_end);
    }
    rec_t *newrec = (rec_t*)rec_newstart;
    DEBUG(DBG_UPDATE, "newrec header old rec_sz: %lu\n", newrec->header.rec_sz);
    newrec->header.rec_sz += diffsz;
    DEBUG(DBG_UPDATE, "newrec header rec_sz: %lu\n", newrec->header.rec_sz);
    if (rec_newstart != rec_oldstart) {
        int record_idx = REC_BLK_IDX(rec, blk);
        blk->bh_record_offsets[record_idx] = new_blk_offset;
    }
    blk->bh_free -= diffsz;
}

void db_log_lasterr(db_t *db) {
    if (db->db_lasterr.err) {
        LOG_ERR("DB Error: %s\n", dbstrerr(db->db_lasterr.err));
        if (db->db_lasterr.err_errno) {
            LOG_ERR("DB Errno errno msg: %s\n", strerror(db->db_lasterr.err_errno));
        }
        if (db->db_lasterr.msg) {
            LOG_ERR("DB Error msg: %s\n", db->db_lasterr.msg);
        }
    }
}

int db_update_records(db_t *db, vec_recinfo_t *vrecinfo, vec_dbsrchcrit_t *vupdate_info, dberr_t *dberr) {
    recinfo_t *recinfo_p;
    int i = 0;
    rec_t *rec;
    blkh_t *blk;
    tbl_t *tbl;
    vec_foreach_ptr(vrecinfo, recinfo_p, i) {
        rec = recinfo_p->rec;
        blk = recinfo_p->blk;
        vec_blkdata_t vholes;
        vec_init(&vholes);
        tbl = db_table_from_id(db, blk->bh_tbl_id);
        dbsrchcrit_t *update_info;
        int j = 0;
        vec_foreach_ptr(vupdate_info, update_info, j) {
            dbval_t curval = REC_DBVAL(rec, update_info->col_idx, update_info->qtype.type);
            size_t cursz = DBVAL_SZ(&curval, &update_info->qtype);
            size_t newsz = DBVAL_SZ(&update_info->val, &update_info->qtype);
            /*DEBUG(DBG_UPDATE, "cursz: %lu, newsz: %lu\n", cursz, newsz);*/
            char *valptr = REC_VALUE_PTR(rec, update_info->col_idx);
            if (newsz < cursz) { // new size less, so it fits
                size_t diffsz = cursz-newsz;
                memcpy(valptr, DBVAL_PTR(&update_info->val, update_info->qtype.type), newsz);
                memset(valptr+newsz, 0, diffsz);
                // TODO: mark a hole if this is the end of the record, or if
                // it's not, move the rest of the record up if it's worth it
                // (diffsz is a big value).
            } else if (newsz > cursz) {
                size_t diffsz = newsz-cursz;
                // We need to find room for the new record value. There are a
                // few scenarios to think of here.
                // 1. We move the start of the record up the block and memcpy the
                // old values up. We can only do this if there's room directly above
                // our record.
                //
                // new:          ------
                //               header
                // old: ------   ==hh==
                //      header   vlcol1
                //      ==hh==   ==xx==
                //      vlcol1   ==yy==
                //      ==aa==   ==zz==
                //      vlcol2   vlcol2
                //      ==bb==   ==bb==
                //      ==bb==   ==bb==
                //      vlcol3   vlcol3
                //      ------   ------
                // 2. We grow the record down, by either
                //   a) Extending the last dbval if it's the last in the record or
                //   b) moving the start of the record down if the growing value isn't
                //      the last dbval
                //
                // 3. We move the record to the start of an arbitrary (big enough) hole in
                // our block and perform step 2 on it.
                if (blk->bh_free >= diffsz) { // FIXME: don't just check bh_free here, check that there a HOLE big enough
                    blk_find_holes(db, blk, &vholes, true);
                    if (blk_has_space_directly_below_record(blk, rec, diffsz, &vholes)) {
                        col_t *col = db_col_from_idx(tbl, update_info->col_idx);
                        char *rec_newstart = PTR(rec);
                        db_grow_record_within_blk(blk, rec, col, rec_newstart, update_info, diffsz);
                    } else if (blk_has_space_directly_above_record(blk, rec, diffsz, &vholes)) {
                        col_t *col = db_col_from_idx(tbl, update_info->col_idx);
                        DEBUG(DBG_UPDATE, "Difference in record size after update: %lu\n", diffsz);
                        char *rec_newstart = PTR(rec)-diffsz;
                        db_grow_record_within_blk(blk, rec, col, rec_newstart, update_info, diffsz);
                        recinfo_p->rec = (rec_t*)rec_newstart;
                    } else { // try to find a hole elsewhere in the block
                        col_t *col = db_col_from_idx(tbl, update_info->col_idx);
                        size_t newrecsz = REC_SZ(rec)+newsz;
                        blkdata_t *hole_found = NULL;
                        hole_found = blk_find_hole_for_record(blk, newrecsz, &vholes);
                        ASSERT(hole_found); // FIXME
                        char *rec_newstart = PTR(blk)+hole_found->blkoff;
                        db_grow_record_within_blk(blk, rec, col, rec_newstart, update_info, diffsz);
                        recinfo_p->rec = (rec_t*)rec_newstart;
                    }
                } else { // have to find new block for this record (or lengthen the block/use block fragments)
                    rec_t *new_rec = NULL;
                    size_t newrecsz = REC_SZ(rec)+diffsz;
                    bool isnewblk = false;
                    uint16_t newrec_blkoff = 0;
                    uint16_t oldrec_blkoff = REC_BLK_OFFSET(rec, blk);
                    blkh_t *newblk = db_find_blk_for_rec(db, tbl, newrecsz, true, &newrec_blkoff, &isnewblk);
                    ASSERT(newblk && newblk != blk);
                    ASSERT(newrec_blkoff > 0 && newrec_blkoff < STOR_PAGESZ);
                    ASSERT(newrec_blkoff > sizeof(blkh_t));
                    DEBUG(DBG_UPDATE, "Moving record from blk (%d) at offset %u to blk " \
                            "(%d) at offset %u: new record size: %lu\n",
                            blk->bh_blkno, oldrec_blkoff, newblk->bh_blkno, newrec_blkoff, newrecsz);
                    int res = db_move_record_to_blk(db, rec, blk, newblk, newrec_blkoff, &new_rec, dberr);
                    ASSERT(res == 0);
                    ASSERT(new_rec);
                    /*DEBUG(DBG_UPDATE, "new record rec_sz: %lu, rectotal_sz: %lu\n", new_rec->header.rec_sz, REC_SZ(new_rec));*/
                    col_t *col = db_col_from_idx(tbl, update_info->col_idx);
                    char *rec_newstart = PTR(new_rec);
                    db_grow_record_within_blk(newblk, new_rec, col, rec_newstart, update_info, diffsz);
                    recinfo_p->rec = new_rec;
                    recinfo_p->blk = newblk;
                    ASSERT(res == 0);
                }
            } else { // same size
                memcpy(valptr, DBVAL_PTR(&update_info->val, update_info->qtype.type), newsz);
            }
        }
        db_mark_blk_dirty(db, blk);
    }
    db_flush_dirty_blks(db);
    return 0;
}

int db_delete_records(db_t *db, vec_recinfo_t *vrecinfo, dberr_t *dberr) {
    recinfo_t *recinfo_p;
    int i = 0;
    rec_t *rec;
    blkh_t *blk;
    vec_foreach_ptr(vrecinfo, recinfo_p, i) {
        rec = recinfo_p->rec;
        blk = recinfo_p->blk;
        ASSERT(blk->bh_num_records > 0);
        int recidx = REC_BLK_IDX(rec, blk);
        ASSERT(recidx != -1);
        int old_num_recs = (int)blk->bh_num_records;
        blk->bh_num_records--;
        size_t rec_sz = REC_SZ(rec);
        blk->bh_free += (rec_sz+sizeof(uint16_t));
        memset(rec, 0, rec_sz);
        size_t tombstone_val = REC_H_TOMBSTONE_VALUE;
        memcpy(rec, &tombstone_val, sizeof(size_t));
        uint16_t rec_offset = REC_BLK_OFFSET(rec, blk);
        blk_mark_new_hole(db, blk, NULL, rec_offset, rec_offset+rec_sz);
        // Update the record offsets in the block header.
        // Example: deleting recidx = 1, old_num_recs = 10
        //   memmove(PTR+1, PTR+2, (10-2)*sizeof(uint16_t))
        if (recidx != (old_num_recs-1)) {
            memmove(blk->bh_record_offsets+recidx,
                    blk->bh_record_offsets+recidx+1,
                    ((old_num_recs-(recidx+1))*sizeof(uint16_t))
            );
        }
        db_mark_blk_dirty(db, blk);
    }
    db_flush_dirty_blks(db);
    return 0;
}

int db_find_record(db_t *db, tbl_t *tbl, vec_dbsrchcrit_t *vsearch_crit, recinfo_t *recinfo_out, dberr_t *dberr) {
    srchopt_t opts;
    opts.limit = 1;
    vec_recinfo_t vrecinfo;
    vec_init(&vrecinfo);
    int res = db_find_records(db, tbl, vsearch_crit, &opts, &vrecinfo, dberr);
    if (res != 0) {
        return res;
    }
    ASSERT(vrecinfo.length <= 1);
    if (vrecinfo.length == 1) {
        *recinfo_out = vrecinfo.data[0];
    }
    return 0;
}

int db_close(db_t *db, dberr_t *dberr) {
    DEBUG(DBG_STATE, "Closing db\n");
    if (db->db_fd <= 0) {
        *dberr = DBERR_DB_NOT_OPEN;
        db_set_lasterr(db, dberr, NULL);
        return -1;
    }
    if (db->db_mt_dirty) {
        DEBUG(DBG_SCHEMA|DBG_STATE, "Flushing metainfo on close (dirty)\n");
        // this call sets dberr, but we still try to close DB even if we get an error here
        db_flush_meta(db, dberr);
    }
    int close_res = close(db->db_fd);
    if (close_res != 0) {
        *dberr = DBERR_ERRNO;
        db_set_lasterr(db, dberr, NULL);
        return close_res;
    }
    db->db_fd = 0;
    db->db_num_writes = 0;
    db->db_offset = 0;
    db->db_mt_dirty = false;
    vec_clear(&db->db_blkcache);
    vec_clear(&db->db_blksdirty);
    memset(&db->db_meta, 0, sizeof(db->db_meta));
    return 0;
}

int db_create(db_t *db, dberr_t *dberr) {
    if (!db->db_fname) {
        *dberr = DBERR_DBNAME_INVALID;
        db_set_lasterr(db, dberr, kstrdup("No database name given"));
    }
    int fd = create_dbfile(db->db_fname);
    if (fd == -1) {
        *dberr = DBERR_ERRNO;
        db_set_lasterr(db, dberr, kstrdup("Couldn't create database file"));
        return -1; // errno set
    }
    db->db_fd = fd;
    return 0;
}

int db_clear(db_t *db, dberr_t *dberr) {
    DEBUG(DBG_STATE, "Clearing db\n");
    if (db->db_fd <= 0) {
        *dberr = DBERR_DB_NOT_OPEN;
        db_set_lasterr(db, dberr, NULL);
        return -1;
    }
    int trunc_res = ftruncate(db->db_fd, 0);
    if (trunc_res != 0) {
        *dberr = DBERR_ERRNO;
        db_set_lasterr(db, dberr, kstrdup("Error truncating file (db_clear)"));
        return -1;
    }
    db->db_offset = 0;
    db->db_mt_dirty = false;
    vec_clear(&db->db_blkcache);
    vec_clear(&db->db_blksdirty);
    vec_clear(&db->db_vblkinfo);
    memset(&db->db_meta, 0, sizeof(db->db_meta));
    db->db_meta.mt_magic = STOR_META_MAGIC;
    return 0;
}

