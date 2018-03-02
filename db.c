#include <stor.h>

uint32_t stor_dbgflags;

void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(1);
}

static void db_set_lasterr(db_t *db, dberr_t *err, char *msg) {
    db->db_lasterr.err = *err;
    if (db->db_lasterr.msg) {
        free(db->db_lasterr.msg);
        db->db_lasterr.msg = msg; // can be NULL
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
    ASSERT(db->db_fd > 0);
    ssize_t res = write(db->db_fd, buf, bufsize);
    if (res == -1) return res;
    if (res != bufsize) return -1;
    db->db_offset += res;
    return res;
}

static ssize_t db_read(db_t *db, void *buf, size_t bufsize) {
    ASSERT(db->db_fd > 0);
    ssize_t res = read(db->db_fd, buf, bufsize);
    if (res == -1) return res;
    db->db_offset += res;
    return res;
}

static int db_load_next_table(db_t *db) {
    tbl_t *tbl = malloc(sizeof(*tbl));
    ASSERT(tbl);
    memset(tbl, 0, sizeof(*tbl));

    size_t tbl_preload_sz = DB_TBL_SER_BYTES_PRELOAD(tbl);
    int res = db_read(db, tbl, tbl_preload_sz);
    if (res == -1) {
        free(tbl);
        return res;
    }
    ASSERT(tbl->tbl_id > 0);
    vec_init(&tbl->tbl_cols);
    vec_init(&tbl->tbl_blks);
    size_t tbl_postload_sz = DB_TBL_SER_BYTES_POSTLOAD(tbl);
    if (tbl_postload_sz > tbl_preload_sz) {
        tbl = realloc(tbl, tbl_postload_sz);
        ASSERT(tbl);
        size_t coldata_sz = sizeof(col_t)*tbl->tbl_num_cols;
        unsigned char *coldata = malloc(coldata_sz);
        ASSERT(coldata);
        res = db_read(db, coldata, coldata_sz);
        if (res == -1) {
            free(tbl); free(coldata);
            return res;
        }
        tbl->tbl_cols.data = (col_t*)coldata;
        tbl->tbl_cols.length = tbl->tbl_cols.capacity = tbl->tbl_num_cols;
        DEBUG(DBG_SCHEMA, "Loaded %d columns for tbl %s\n", tbl->tbl_num_cols, tbl->tbl_name);
        col_t *firstcol = (col_t*)coldata;
        DEBUG(DBG_SCHEMA, "first col type: %d, col name: %s\n", firstcol->col_type, firstcol->col_name);
        /*col_t *seccol = (col_t*)coldata+1;*/
        /*DEBUG(DBG_SCHEMA, "second col type: %d, col name: %s\n", seccol->col_type, seccol->col_name);*/
        if (tbl->tbl_num_blks > 0) {
            size_t blkdata_sz = sizeof(uint16_t)*tbl->tbl_num_blks;
            unsigned char *blkdata = malloc(blkdata_sz);
            ASSERT(blkdata);
            res = db_read(db, blkdata, blkdata_sz);
            if (res == -1) {
                free(tbl); free(coldata); free(blkdata);
                return res;
            }
            tbl->tbl_blks.data = (uint16_t*)blkdata;
            tbl->tbl_blks.length = tbl->tbl_blks.capacity = tbl->tbl_num_blks;
        }
    }
    vec_push(&db->db_meta.mt_tbls, tbl);
    return 0;
}

static int db_load_meta(db_t *db) {
    int res = db_read(db, &db->db_meta, DB_META_SER_BYTES(&db->db_meta));
    if (res == -1) return res;
    if (db->db_meta.mt_magic != STOR_META_MAGIC) {
        die("Unable to load database (maybe corrupted?): invalid header\n");
    }
    if (db->db_meta.mt_num_tables > 0) {
        for (int i = 0; i < db->db_meta.mt_num_tables; i++) {
            res = db_load_next_table(db);
            if (res == -1) return res;
        }
    }
    return 0;
}

int db_load(db_t *db) {
    ASSERT(db->db_fname);
    ASSERT(db->db_fd == 0);
    int fd = open(db->db_fname, O_RDWR);
    if (fd == -1) return -1;
    db->db_fd = fd;
    int load_res = db_load_meta(db);
    if (load_res != 0) return load_res;
    ASSERT(db->db_meta.mt_sersize > 0);
    return 0;
}

tbl_t *db_table(db_t *db, int i) {
    ASSERT(i >= 0 && i < db->db_meta.mt_tbls.length);
    return db->db_meta.mt_tbls.data[i];
}

col_t *db_col(tbl_t *tbl, int i) {
    ASSERT(i < tbl->tbl_num_cols);
    return &tbl->tbl_cols.data[i];
}

static col_t *db_colname(tbl_t *tbl, const char *name, int *colidx) {
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

int db_flush_meta(db_t *db) {
    if (db->db_fd <= 0) {
        return -1;
    }
    if (!db->db_mt_dirty) {
        return -1;
    }
    int seek_res, write_res;
    seek_res = db_seek(db, SEEK_SET, 0);
    if (seek_res != 0) return seek_res;
    ASSERT(db->db_meta.mt_magic == STOR_META_MAGIC);
    size_t meta_bytes = DB_META_SER_BYTES(&db->db_meta);
    write_res = db_write(db, &db->db_meta, meta_bytes);
    if (write_res == -1) return write_res;
    for (int i = 0; i < db->db_meta.mt_num_tables; i++) {
        tbl_t *tbl = db_table(db, i);
        ASSERT(tbl);
        size_t fulltbl_sz = DB_TBL_SER_BYTES_POSTLOAD(tbl);
        unsigned char *tblbuf = malloc(fulltbl_sz);
        ASSERT(tblbuf);
        memcpy(tblbuf, tbl, sizeof(*tbl));
        col_t *curcol;
        int i = 0;
        unsigned char *tblbufp = tblbuf+sizeof(*tbl);
        vec_foreach_ptr(&tbl->tbl_cols, curcol, i) {
            memcpy(tblbufp, curcol, sizeof(*curcol));
            tblbufp += sizeof(*curcol);
        }
        i = 0;
        uint16_t curblk = 0;
        vec_foreach(&tbl->tbl_blks, curblk, i) {
            memcpy(tblbufp, &curblk, sizeof(curblk));
            tblbufp += sizeof(curblk);
        }
        ASSERT(tblbufp - tblbuf == fulltbl_sz);
        write_res = db_write(db, tblbuf, fulltbl_sz);
        if (write_res == -1) {
            free(tblbuf);
            return write_res;
        }
    }
    db->db_meta.mt_sersize = (size_t)db->db_offset;
    seek_res = db_seek(db, SEEK_SET, 4);
    if (seek_res != 0) return seek_res;
    write_res = write(db->db_fd, &db->db_meta.mt_sersize, sizeof(size_t));
    if (write_res == -1) return write_res;
    seek_res = db_seek(db, SEEK_SET, 0);
    if (seek_res != 0) return seek_res;
    db->db_mt_dirty = false;
    return 0;
}

static coltype_t coltype(char *coltype) {
    if (strncmp(coltype, "int", 10) == 0) {
        return COLTYPE_INT;
    } else if (strncmp(coltype, "char", 10) == 0) {
        return COLTYPE_CHAR;
    } else if (strncmp(coltype, "varchar", 10) == 0) {
        return COLTYPE_VARCHAR;
    } else if (strncmp(coltype, "double", 10) == 0) {
        return COLTYPE_DOUBLE;
    } else {
        return COLTYPE_ERR;
    }
}

const char *coltype_str(coltype_t coltype) {
    switch(coltype) {
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

int db_add_table(db_t *db, const char *tblname, const char *colinfo, dberr_t *dberr) {
    if (strnlen(tblname, STOR_TBLNAME_MAX)+1 > STOR_TBLNAME_MAX) {
        *dberr = DBERR_TBLNAME_TOO_LONG;
        db_set_lasterr(db, dberr, strndup(tblname, STOR_TBLNAME_MAX));
        return -1;
    }
    int num_tbls = db->db_meta.mt_num_tables;
    tblid_t new_id = 1;
    for (int i = 0; i < num_tbls; i++) {
        tbl_t *tbl = db_table(db, i);
        ASSERT(tbl->tbl_id > 0);
        if (strcmp(tblname, tbl->tbl_name) == 0) {
            *dberr = DBERR_TBLNAME_EXISTS;
            db_set_lasterr(db, dberr, strndup(tblname, STOR_TBLNAME_MAX));
            return -1;
        }
        if (tbl->tbl_id >= new_id) {
            new_id = tbl->tbl_id+1;
        }
    }
    struct stordb_tbl *newtbl = malloc(sizeof(*newtbl));
    ASSERT(newtbl);
    memset(newtbl, 0, sizeof(*newtbl));
    newtbl->tbl_id = new_id;
    strncpy(newtbl->tbl_name, tblname, STOR_TBLNAME_MAX);
    newtbl->tbl_num_cols = 0;
    newtbl->tbl_num_blks = 0;
    vec_init(&newtbl->tbl_cols);
    vec_init(&newtbl->tbl_blks);

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
            db_set_lasterr(db, dberr, strndup(colbeg, STOR_COLNAME_MAX));
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
        struct stordb_col *newcol = malloc(sizeof(*newcol));
        ASSERT(newcol);
        memset(newcol, 0, sizeof(*newcol));
        newcol->col_id = (new_id * 1000) + numcols;
        memset(colnamebuf, 0, sizeof(colnamebuf));
        memset(coltypebuf, 0, sizeof(coltypebuf));
        DEBUG(DBG_SCHEMA, "Adding column %d (%d)\n", (int)colnamelen, (int)coltypelen);
        strncpy(colnamebuf, colbeg, colnamelen);
        strncpy(coltypebuf, coltypebeg, coltypelen);
        strncpy(newcol->col_name, colnamebuf, colnamelen);
        coltype_t col_type = coltype(coltypebuf);
        if (col_type == COLTYPE_ERR) {
            LOG_ERR("Invalid column type: %s\n", coltypebuf);
            *dberr = DBERR_COLTYPE_INVALID;
            db_set_lasterr(db, dberr, strndup(coltypebuf, coltypelen));
            err = true;
            break;
        }
        DEBUG(DBG_SCHEMA, "Adding column '%s', type: '%s'\n", colnamebuf, coltypebuf);
        newcol->col_type = col_type;
        newtbl->tbl_num_cols++;
        vec_push(&newtbl->tbl_cols, *newcol);
    } while (colbegnext != NULL);

    if (err) {
        free(newtbl);
        return -1;
    }

    vec_push(&db->db_meta.mt_tbls, newtbl);

    db->db_mt_dirty = true;
    db->db_meta.mt_num_tables++;
    db_flush_meta(db);
    return 0;
}

static int db_deserialize_val(db_t *db, char *dbval, coltype_t dbtype, dbtval_t *tval, size_t *valsz, dberr_t *dberr) {
    tval->type = dbtype;
    switch (dbtype) {
        case COLTYPE_INT: {
            long val = strtol(dbval, NULL, 10);
            if (val < INT_MIN || val > INT_MAX) {
                DEBUG(DBG_DESER, "int out of range: %s\n", dbval);
                *dberr = DBERR_VAL_OUT_OF_RANGE;
                db_set_lasterr(db, dberr, strndup(dbval, 12));
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
                db_set_lasterr(db, dberr, strndup(dbval, 10));
                return -1;
            }
            tval->val = (dbval_t)c;
            if (valsz) {
                *valsz = sizeof(char);
            }
            break;
        }
        case COLTYPE_VARCHAR: {
            size_t len = strnlen(dbval, STOR_VARCHAR_MAX+1);
            if (len > STOR_VARCHAR_MAX) {
                *dberr = DBERR_VAL_OUT_OF_RANGE;
                db_set_lasterr(db, dberr, strndup(dbval, STOR_VARCHAR_MAX));
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
                db_set_lasterr(db, dberr, strndup(dbval, 12));
                return -1;
            }
            tval->val = (dbval_t)val;
            if (valsz) {
                *valsz = sizeof(double);
            }
            break;
        }
        default:
            *dberr = DBERR_COLTYPE_INVALID;
            return -1;
    }
    return 0;
}

blkh_t *db_load_blk(db_t *db, uint16_t num) {
    int i = 0;
    blkh_t *cachedblk;
    vec_foreach(&db->db_blkcache, cachedblk, i) {
        if (cachedblk->bh_blkno == num) {
            return cachedblk;
        }
    }
    off_t offset = num * STOR_BLKSIZ;
    int seek_res = db_seek(db, SEEK_SET, offset);
    if (seek_res != 0) {
        return NULL;
    }
    unsigned char *blk = malloc(STOR_BLKSIZ);
    ASSERT(blk);
    int res = db_read(db, blk, STOR_BLKSIZ);
    if (res <= 0) return NULL;
    vec_push(&db->db_blkcache, (blkh_t*)blk);
    return (blkh_t*)blk;
}

static blkh_t *db_alloc_blk(db_t *db, uint16_t num, tbl_t *tbl) {
    off_t offset = num * STOR_BLKSIZ;
    int seek_res = db_seek(db, SEEK_SET, offset);
    if (seek_res != 0) {
        return NULL;
    }
    struct stordb_blk_h *blk = malloc(STOR_BLKSIZ);
    memset(blk, 0, STOR_BLKSIZ);
    ASSERT(blk);
    blk->bh_magic = STOR_BLKH_MAGIC;
    blk->bh_tbl_id = tbl->tbl_id;
    blk->bh_blkno = num;
    blk->bh_num_records = 0;
    blk->bh_free = STOR_BLKSIZ - sizeof(*blk);
    int res = db_write(db, blk, STOR_BLKSIZ);
    if (res <= 0) return NULL;
    vec_push(&tbl->tbl_blks, num);
    tbl->tbl_num_blks++;
    return blk;
}

static int db_flush_blk(db_t *db, blkh_t *blk) {
    ASSERT(blk->bh_blkno > 0);
    int res = db_seek(db, SEEK_SET, blk->bh_blkno * STOR_BLKSIZ);
    if (res != 0) return res;
    ssize_t write_res = db_write(db, blk, STOR_BLKSIZ);
    if (write_res != STOR_BLKSIZ) {
        return -1;
    }
    return 0;
}

static int db_flush_dirty_blks(db_t *db) {
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

blkh_t *db_find_blk_for_rec(db_t *db, tbl_t *tbl, size_t recsz, bool alloc_if_not_found, bool *isnewblk) {
    ASSERT(recsz < STOR_BLKSIZ); // TODO: implement record fragments across blocks
    blkh_t *found = NULL;
    blkh_t *blk = NULL;
    uint16_t num = 1;
    do {
        blk = db_load_blk(db, num);
        if (blk == NULL || blk->bh_magic != STOR_BLKH_MAGIC) {
            break;
        }
        if (blk->bh_free >= (recsz+2)) {
            found = blk;
            break;
        }
        num++;
    } while (found == NULL && blk != NULL);
    if (!found && !alloc_if_not_found) {
        return NULL;
    }
    if (!found) { // alloc
        blk = db_alloc_blk(db, num, tbl);
        ASSERT(blk);
        if (isnewblk != NULL) {
            *isnewblk = true;
        }
        return blk;
    } else {
        return found;
    }
}

static bool db_blk_fits_rec(blkh_t *blkh, rec_t *rec) {
    size_t recsz_total = rec->header.rech_sz+rec->header.rec_sz;
    return blkh->bh_free >= (recsz_total+2);
}

// Add a record to the in-memory representation of a data block. Caller must
// check that there's room before calling.
static int db_blk_add_rec(db_t *db, blkh_t *blkh, rec_t *rec) {
    size_t recsz_total = rec->header.rech_sz+rec->header.rec_sz;
    ASSERT(db_blk_fits_rec(blkh, rec));
    char *writestart = NULL;
    off_t rec_offset;
    if (blkh->bh_num_records == 0) {
        rec_offset = STOR_BLKSIZ - recsz_total;
    } else {
        rec_offset = blkh->bh_record_offsets[blkh->bh_num_records-1] - recsz_total;
        ASSERT(rec_offset > 0 && rec_offset < STOR_BLKSIZ);
    }
    DEBUG(DBG_ADD, "Writing record (%lu bytes) at offset: %ld\n", recsz_total, rec_offset);
    DEBUG(DBG_ADD, "Writing record, blkh ptr: %p\n", blkh);
    DEBUG(DBG_ADD, "Writing record, blkh ptr+offset: %p\n", ((char*)blkh)+rec_offset);
    /*DEBUG(DBG_ADD, "Record header offset 0: %ld\n", rec->header.rec_offsets[0]);*/
    /*DEBUG(DBG_ADD, "Record header offset 1: %ld\n", rec->header.rec_offsets[1]);*/
    /*DEBUG(DBG_ADD, "First rec value: %d\n", *(int*)REC_VALUES_PTR(rec));*/
    /*DEBUG(DBG_ADD, "Second rec value: %s\n", (char*)REC_VALUE_PTR(rec,1));*/
    writestart = ((char*)blkh)+rec_offset;
    memcpy(writestart, rec, recsz_total);
    blkh->bh_free -= (recsz_total + 2); // add 2 bytes to account for storing offset (see below)
    blkh->bh_num_records++;
    blkh->bh_record_offsets[blkh->bh_num_records-1] = rec_offset;
    return 0;
}

int db_add_record(db_t *db, const char *tblname, const char *rowvals, blkh_t **blkh_out, bool flushblk, dberr_t *dberr) {
    const char *valsep = ",";
    tbl_t *cur = NULL;
    tbl_t *tbl = NULL;
    int i = 0;
    vec_foreach(&db->db_meta.mt_tbls, cur, i) {
        if (strcmp(cur->tbl_name, tblname) == 0) {
            tbl = cur;
            break;
        }
    }
    if (!tbl) {
        *dberr = DBERR_TBLNAME_NOEXIST;
        db_set_lasterr(db, dberr, strndup(tblname, STOR_TBLNAME_MAX));
        return -1;
    }
    char *tok = NULL;
    char *in = (char*)rowvals;
    size_t val_sizes[tbl->tbl_num_cols];
    dbtval_t vals[tbl->tbl_num_cols];
    size_t recsz_total = 0;
    int validx = 0;
    while ((tok = strtok(in, valsep)) != NULL) {
        col_t *col = db_col(tbl, validx);
        if (!col) {
            *dberr = DBERR_TOO_MANY_REC_VALUES;
            db_set_lasterr(db, dberr, strndup(tok, 100));
            return -1;
        }
        dbtval_t tval;
        dberr_t deser_err;
        size_t valsz = 0;
        int res = db_deserialize_val(db, tok, col->col_type, &tval, &valsz, &deser_err);
        if (res == -1) {
            *dberr = deser_err;
            return -1;
        }
        ASSERT(valsz > 0);
        val_sizes[validx] = valsz;
        vals[validx] = tval;
        recsz_total += valsz;
        validx++;
        in = NULL;
    }
    size_t rech_sz = sizeof(struct stordb_rec_h) + sizeof(off_t)*tbl->tbl_num_cols;
    rech_t *rech = malloc(rech_sz);
    ASSERT(rech);
    memset(rech, 0, rech_sz);
    rech->rech_sz = rech_sz;
    rech->rec_sz = recsz_total;
    off_t *rec_offsets = rech->rec_offsets;
    off_t rec_off = 0;
    for (int i = 0; i < tbl->tbl_num_cols; i++) {
        DEBUG(DBG_ADD, "Saving record offset: %ld for colidx %d\n", rec_off, i);
        rec_offsets[i] = rec_off;
        rec_off += val_sizes[i];
    }
    size_t recsz_all = rech_sz+rech->rec_sz;
    rec_t *rec = malloc(recsz_all);
    ASSERT(rec);
    memset(rec, 0, recsz_all);
    memcpy(rec, rech, rech_sz);
    ASSERT(rec->header.rech_sz == rech->rech_sz);
    ASSERT(rec->header.rec_sz == rech->rec_sz);
    char *rec_vals = REC_VALUES_PTR(rec);
    for (int i = 0; i < tbl->tbl_num_cols; i++) {
        ASSERT(val_sizes[i] > 0);
        switch (vals[i].type) {
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
    blkh_t *blkh = db_find_blk_for_rec(db, tbl, recsz_all, true, &isnewblk);
    ASSERT(blkh);
    if (blkh_out != NULL) {
        *blkh_out = blkh;
    }
    int add_res = db_blk_add_rec(db, blkh, rec);
    if (add_res != 0) return add_res;
    if (flushblk) {
        db_flush_blk(db, blkh);
    }
    db->db_mt_dirty = isnewblk;
    return 0;
}

static bool record_val_matches(dbtval_t *recval, dbsrchcrit_t *srchcrit) {
    ASSERT(recval->type == srchcrit->type && recval->type > COLTYPE_ERR);
    switch(recval->type) {
        case COLTYPE_INT:
            DEBUG(DBG_SRCH, "FIND [INT] => recval: %d, srchcrit: %d\n", recval->val.ival, srchcrit->val.ival);
            return recval->val.ival == srchcrit->val.ival;
        case COLTYPE_CHAR:
            DEBUG(DBG_SRCH, "FIND [CHAR] => recval: %c, srchcrit: %c\n", recval->val.cval, srchcrit->val.cval);
            return recval->val.cval == srchcrit->val.cval;
        case COLTYPE_VARCHAR:
            DEBUG(DBG_SRCH, "FIND [VARCHAR] => recval: %s, srchcrit: %s\n", recval->val.sval, srchcrit->val.sval);
            return strncmp(recval->val.sval, srchcrit->val.sval, STOR_VARCHAR_MAX) == 0;
        case COLTYPE_DOUBLE:
            DEBUG(DBG_SRCH, "FIND [DOUBLE] => recval: %f, srchcrit: %f\n", recval->val.dval, srchcrit->val.dval);
            return recval->val.dval == srchcrit->val.dval;
        default:
            die("unreachable\n");
            return false;
    }
}

static dbval_t REC_DBVAL(rec_t *rec, int colidx, coltype_t type) {
    if (type == COLTYPE_VARCHAR) {
        return (dbval_t)REC_VALUE_PTR(rec, colidx);
    } else {
        return *(dbval_t*)REC_VALUE_PTR(rec, colidx);
    }
}

static void *DBVAL_PTR(dbval_t *dbval, coltype_t type) {
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
        tval.type = search_crit->type;
        dbval_t val;
        DEBUG(DBG_SRCH, "record value offset for col idx %d: %ld\n",
            search_crit->col_idx, offset
        );
        val = REC_DBVAL(rec, search_crit->col_idx, tval.type);
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
    const char *valcolsep = ",";
    char *tok = NULL;
    char *in = (char*)srchcrit_str;
    int idx = 0;
    int colidx;
    col_t *col = NULL;
    while ((tok = strtok(in, idx % 2 == 0 ? colvalsep : valcolsep)) != NULL) {
        // parse column name
        if (idx % 2 == 0) {
            col = db_colname(tbl, tok, &colidx);
            if (!col) {
                *dberr = DBERR_COLNAME_NOEXIST;
                db_set_lasterr(db, dberr, strndup(tok, STOR_COLNAME_MAX));
                return -1;
            }
        // parse record value
        } else {
            dbtval_t tval;
            dberr_t deser_err;
            int res = db_deserialize_val(db, tok, col->col_type, &tval, NULL, &deser_err);
            if (res == -1) {
                *dberr = deser_err;
                return -1;
            }
            dbsrchcrit_t srchcrit;
            srchcrit.tbl_id = tbl->tbl_id;
            srchcrit.col_id = col->col_id;
            srchcrit.col_idx = colidx;
            srchcrit.val = tval.val;
            srchcrit.type = tval.type;
            vec_push(vsearch_crit, srchcrit);
        }
        idx++;
        in = NULL;
    }

    // "col1=val1,col2=", we're missing a value
    if (idx % 2 != 0) {
        *dberr = DBERR_MISSING_FIND_VALUE;
        db_set_lasterr(db, dberr, strndup(col->col_name, STOR_COLNAME_MAX));
        return -1;
    }

    db_sort_srchcrit(tbl, vsearch_crit);
    return 0;
}

tbl_t *db_find_table(db_t *db, const char *tblname) {
    tbl_t *curtbl = NULL;
    int i = 0;
    vec_foreach(&db->db_meta.mt_tbls, curtbl, i) {
        if (strncmp(curtbl->tbl_name, tblname, STOR_TBLNAME_MAX) == 0) {
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
    vec_foreach(&tbl->tbl_blks, blkno, blkidx) {
        blk = db_load_blk(db, blkno);
        ASSERT(blk);
        if (blk->bh_num_records == 0) {
            continue;
        }
        rec_t *rec;
        int recidx = 0;
        int num_found = 0;
        BLK_RECORDS_FOREACH(blk, rec, recidx) {
            /*ASSERT(!REC_IS_TOMBSTONED(rec));*/
            if (REC_IS_TOMBSTONED(rec)) {
                continue;
            }
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

static size_t dbval_sz(dbval_t *val, coltype_t type) {
    switch(type) {
        case COLTYPE_INT:
            return sizeof(int);
        case COLTYPE_DOUBLE:
            return sizeof(double);
        case COLTYPE_CHAR:
            return 1;
        case COLTYPE_VARCHAR:
            ASSERT(val->sval);
            return strnlen(val->sval, STOR_VARCHAR_MAX);
        default:
            LOG_ERR("invalid type for dbval: %d\n", type);
            return 0;
    }
}

static void db_mark_blk_dirty(db_t *db, blkh_t *blk) {
    int idx = 0;
    vec_find(&db->db_blksdirty, (int)blk->bh_blkno, idx);
    if (idx == -1) {
        vec_push(&db->db_blksdirty, (int)blk->bh_blkno);
    }
}

/*static void db_unmark_blk_dirty(db_t *db, blkh_t *blk) {*/
    /*vec_remove(&db->db_blksdirty, (int)blk->bh_blkno);*/
/*}*/

int db_update_records(db_t *db, vec_recinfo_t *vrecinfo, vec_dbsrchcrit_t *vupdate_info, dberr_t *dberr) {
    recinfo_t *recinfo_p;
    int i = 0;
    rec_t *rec;
    blkh_t *blk;
    vec_foreach_ptr(vrecinfo, recinfo_p, i) {
        /*size_t size_diff = 0;*/
        rec = recinfo_p->rec;
        blk = recinfo_p->blk;
        dbsrchcrit_t *update_info;
        int j = 0;
        vec_foreach_ptr(vupdate_info, update_info, j) {
            dbval_t curval = REC_DBVAL(rec, update_info->col_idx, update_info->type);
            size_t cursz = dbval_sz(&curval, update_info->type);
            size_t newsz = dbval_sz(&update_info->val, update_info->type);
            // TODO: handle VARCHAR record re-sizing and moving to new block, tombstoning old record
            ASSERT(cursz == newsz);
            char *ptr = REC_VALUE_PTR(rec, update_info->col_idx);
            memcpy(ptr, DBVAL_PTR(&update_info->val, update_info->type), newsz);
        }
        db_mark_blk_dirty(db, blk);
    }
    db_flush_dirty_blks(db);
    return 0;
}

static int REC_BLK_IDX(rec_t *rec, blkh_t *blk) {
    for (int i = 0; i < blk->bh_num_records; i++) {
        if (((char*)blk)+blk->bh_record_offsets[i] == (char*)rec) {
            return i;
        }
    }
    return -1;
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

int db_close(db_t *db) {
    DEBUG(DBG_STATE, "Closing db\n");
    if (db->db_fd <= 0) {
        return -1;
    }
    if (db->db_mt_dirty) {
        DEBUG(DBG_SCHEMA|DBG_STATE, "Flushing metainfo on close (dirty)\n");
        db_flush_meta(db);
    }
    int close_res = close(db->db_fd);
    if (close_res != 0) return close_res;
    db->db_fd = 0;
    return 0;
}

int db_init(db_t *db) {
    if (!db->db_fname) {
        return -1;
    }
    int fd = create_dbfile(db->db_fname);
    if (fd == -1) {
        return -1; // errno set
    }
    db->db_fd = fd;
    return 0;
}

