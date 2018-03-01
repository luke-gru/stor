#include <stor.h>

static const char empty_blk[STOR_BLKSIZ];
uint32_t stor_dbgflags;

void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(1);
}

static void db_set_lasterr(struct stordb *db, dberr_t *err, char *msg) {
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

static int db_seek(struct stordb *db, int whence, off_t offset) {
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

/*static off_t db_first_records_offset(struct stordb *db) {*/
    /*size_t metasz = db->db_meta.mt_sersize;*/
    /*DEBUG(DBG_SCHEMA, "mt_sersize: %d\n", (int)metasz);*/
    /*ASSERT(metasz >= DB_META_SERIALIZABLE_BYTES(&db->db_meta));*/
    /*if (metasz % STOR_BLKSIZ == 0) {*/
        /*return (off_t)metasz;*/
    /*} else {*/
        /*size_t remaining_bytes = STOR_BLKSIZ - (metasz % STOR_BLKSIZ);*/
        /*return (off_t)(metasz + remaining_bytes);*/
    /*}*/
/*}*/

static ssize_t db_write(struct stordb *db, void *buf, size_t bufsize) {
    ASSERT(db->db_fd > 0);
    ssize_t res = write(db->db_fd, buf, bufsize);
    if (res == -1) return res;
    if (res != bufsize) return -1;
    db->db_offset += res;
    return res;
}
static ssize_t db_read(struct stordb *db, void *buf, size_t bufsize) {
    ASSERT(db->db_fd > 0);
    ssize_t res = read(db->db_fd, buf, bufsize);
    if (res == -1) return res;
    db->db_offset += res;
    return res;
}

/*static ssize_t db_write_blks(struct stordb *db, void *buf, size_t bufsize, bool pad_with_zeros) {*/
    /*ASSERT(db->db_offset % STOR_BLKSIZ == 0);*/
    /*off_t old_offset = db->db_offset;*/
    /*ssize_t res = db_write(db, buf, bufsize);*/
    /*if (res == -1) {*/
        /*return res;*/
    /*}*/
    /*if (pad_with_zeros && res % STOR_BLKSIZ != 0) {*/
        /*size_t remaining_bytes = STOR_BLKSIZ - (res % STOR_BLKSIZ);*/
        /*ASSERT(remaining_bytes < STOR_BLKSIZ);*/
        /*res = db_write(db, (void*)empty_blk, remaining_bytes);*/
        /*if (res == -1) return res;*/
    /*}*/
    /*return (ssize_t)(db->db_offset - old_offset);*/
/*}*/

/*static int db_load_col(struct stordb *db, struct stordb_tbl *tbl, struct stordb_col **colout) {*/
    /*int res = db_read(db, *colout, DB_COL_SER_BYTES(*colout));*/
    /*if (res == -1) return res;*/
    /*return 0;*/
/*}*/

static int db_load_next_table(struct stordb *db) {
    struct stordb_tbl *tbl = malloc(sizeof(*tbl));
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
        size_t coldata_sz = sizeof(struct stordb_col)*tbl->tbl_num_cols;
        unsigned char *coldata = malloc(coldata_sz);
        ASSERT(coldata);
        res = db_read(db, coldata, coldata_sz);
        if (res == -1) {
            free(tbl); free(coldata);
            return res;
        }
        tbl->tbl_cols.data = (struct stordb_col*)coldata;
        tbl->tbl_cols.length = tbl->tbl_cols.capacity = tbl->tbl_num_cols;
        DEBUG(DBG_SCHEMA, "Loaded %d columns for tbl %s\n", tbl->tbl_num_cols, tbl->tbl_name);
        struct stordb_col *firstcol = (struct stordb_col*)coldata;
        DEBUG(DBG_SCHEMA, "first col type: %d, col name: %s\n", firstcol->col_type, firstcol->col_name);
        struct stordb_col *seccol = (struct stordb_col*)coldata+1;
        DEBUG(DBG_SCHEMA, "second col type: %d, col name: %s\n", seccol->col_type, seccol->col_name);
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

static int db_load_meta(struct stordb *db) {
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
    //res = db_seek(db, SEEK_SET, db_first_records_offset(db));
    //if (res != 0) return res;
    return 0;
}

static int db_load(struct stordb *db) {
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

static struct stordb_tbl *db_table(struct stordb *db, int i) {
    ASSERT(i >= 0 && i < db->db_meta.mt_tbls.length);
    return db->db_meta.mt_tbls.data[i];
}

static struct stordb_col *db_col(struct stordb_tbl *tbl, int i) {
    ASSERT(i < tbl->tbl_num_cols);
    return &tbl->tbl_cols.data[i];
}

static struct stordb_col *db_colname(struct stordb_tbl *tbl, const char *name, int *colidx) {
    struct stordb_col *col;
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

static int db_flush_meta(struct stordb *db) {
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
        struct stordb_tbl *tbl = db_table(db, i);
        ASSERT(tbl);
        size_t fulltbl_sz = DB_TBL_SER_BYTES_POSTLOAD(tbl);
        unsigned char *tblbuf = malloc(fulltbl_sz);
        ASSERT(tblbuf);
        memcpy(tblbuf, tbl, sizeof(*tbl));
        struct stordb_col *curcol;
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

static enum stor_coltype coltype(char *coltype) {
    if (strcmp(coltype, "int") == 0) {
        return COLTYPE_INT;
    } else if (strcmp(coltype, "char") == 0) {
        return COLTYPE_CHAR;
    } else if (strcmp(coltype, "varchar") == 0) {
        return COLTYPE_VARCHAR;
    } else if (strcmp(coltype, "double") == 0) {
        return COLTYPE_DOUBLE;
    } else {
        return COLTYPE_ERR;
    }
}

static const char *coltype_str(enum stor_coltype coltype) {
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

static int db_add_table(struct stordb *db, const char *tblname, const char *colinfo, dberr_t *dberr) {
    if (strnlen(tblname, STOR_TBLNAME_MAX)+1 > STOR_TBLNAME_MAX) {
        *dberr = DBERR_TBLNAME_TOO_LONG;
        db_set_lasterr(db, dberr, strndup(tblname, STOR_TBLNAME_MAX));
        return -1;
    }
    int num_tbls = db->db_meta.mt_num_tables;
    tblid_t new_id = 1;
    for (int i = 0; i < num_tbls; i++) {
        struct stordb_tbl *tbl = db_table(db, i);
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
    DEBUG(DBG_SCHEMA, "Got here\n");
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

static int db_deserialize_val(struct stordb *db, char *dbval, enum stor_coltype dbtype, dbtval_t *tval, size_t *valsz, dberr_t *dberr) {
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

struct stordb_blk_h *db_load_blk(struct stordb *db, uint16_t num) {
    int i = 0;
    struct stordb_blk_h *cachedblk;
    vec_foreach(&db->db_blkcache, cachedblk, i) {
        if (cachedblk->bh_blknum == num) {
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
    vec_push(&db->db_blkcache, (struct stordb_blk_h*)blk);
    return (struct stordb_blk_h*)blk;
}

struct stordb_blk_h *db_alloc_blk(struct stordb *db, uint16_t num, struct stordb_tbl *tbl) {
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
    blk->bh_blknum = num;
    blk->bh_num_records = 0;
    blk->bh_free = STOR_BLKSIZ - sizeof(*blk);
    int res = db_write(db, blk, STOR_BLKSIZ);
    if (res <= 0) return NULL;
    vec_push(&tbl->tbl_blks, num);
    tbl->tbl_num_blks++;
    return blk;
}

static int db_flush_blk(struct stordb *db, struct stordb_blk_h *blk) {
    ASSERT(blk->bh_blknum > 0);
    int res = db_seek(db, SEEK_SET, blk->bh_blknum * STOR_BLKSIZ);
    if (res != 0) return res;
    ssize_t write_res = db_write(db, blk, STOR_BLKSIZ);
    if (write_res != STOR_BLKSIZ) {
        return -1;
    }
    return 0;
}

struct stordb_blk_h *db_find_blk_for_rec(struct stordb *db, struct stordb_tbl *tbl, size_t recsz, bool alloc_if_not_found) {
    ASSERT(recsz < STOR_BLKSIZ); // TODO: implement record fragments across blocks
    struct stordb_blk_h *found = NULL;
    struct stordb_blk_h *blk = NULL;
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
        return blk;
    } else {
        return found;
    }
}

static int db_blk_add_rec(struct stordb *db, struct stordb_blk_h *blkh, struct stordb_rec *rec) {
    size_t recsz_total = rec->header.rech_sz+rec->header.rec_sz;
    ASSERT(blkh->bh_free >= recsz_total);
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

static int db_add_record(struct stordb *db, const char *tblname, const char *rowvals, dberr_t *dberr) {
    const char *valsep = ",";
    struct stordb_tbl *cur = NULL;
    struct stordb_tbl *tbl = NULL;
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
        struct stordb_col *col = db_col(tbl, validx);
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
    struct stordb_rec_h *rech = malloc(rech_sz);
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
    struct stordb_rec *rec = malloc(recsz_all);
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
    struct stordb_blk_h *blkh = db_find_blk_for_rec(db, tbl, recsz_all, true);
    ASSERT(blkh);
    bool added_blk = blkh->bh_num_records == 0;
    int add_res = db_blk_add_rec(db, blkh, rec);
    if (add_res != 0) return add_res;
    db_flush_blk(db, blkh);
    db->db_mt_dirty = added_blk;
    return 0;
}

static bool record_val_matches(dbtval_t *recval, dbsrchval_t *srchval) {
    ASSERT(recval->type == srchval->type && recval->type > COLTYPE_ERR);
    switch(recval->type) {
        case COLTYPE_INT:
            DEBUG(DBG_SRCH, "FIND [INT] => recval: %d, srchval: %d\n", recval->val.ival, srchval->val.ival);
            return recval->val.ival == srchval->val.ival;
        case COLTYPE_CHAR:
            DEBUG(DBG_SRCH, "FIND [CHAR] => recval: %c, srchval: %c\n", recval->val.cval, srchval->val.cval);
            return recval->val.cval == srchval->val.cval;
        case COLTYPE_VARCHAR:
            DEBUG(DBG_SRCH, "FIND [VARCHAR] => recval: %s, srchval: %s\n", recval->val.sval, srchval->val.sval);
            return strncmp(recval->val.sval, srchval->val.sval, STOR_VARCHAR_MAX) == 0;
        case COLTYPE_DOUBLE:
            DEBUG(DBG_SRCH, "FIND [DOUBLE] => recval: %f, srchval: %f\n", recval->val.dval, srchval->val.dval);
            return recval->val.dval == srchval->val.dval;
        default:
            die("unreachable\n");
            return false;
    }
}

static bool db_record_matches(struct stordb_rec *rec, vec_dbsrchval_t *search_vals) {
    dbsrchval_t *search_val;
    int idx;
    vec_foreach_ptr(search_vals, search_val, idx) {
        off_t offset = rec->header.rec_offsets[search_val->col_idx];
        if (search_val->col_idx > 0) {
            ASSERT(offset > 0);
        } else if (search_val->col_idx == 0) {
            ASSERT(offset == 0);
        }
        dbtval_t tval;
        tval.type = search_val->type;
        dbval_t val;
        DEBUG(DBG_SRCH, "record value offset for col idx %d: %ld\n", search_val->col_idx, offset);
        if (tval.type == COLTYPE_VARCHAR) {
            val = (dbval_t)REC_VALUE_PTR(rec, search_val->col_idx);
        } else {
            val = *(dbval_t*)REC_VALUE_PTR(rec, search_val->col_idx);
        }
        tval.val = val;
        /*if (tval.type == COLTYPE_INT) {*/
            /*DEBUG(DBG_SRCH, "record value for int: %d\n", tval.val.ival);*/
        /*}*/
        /*if (tval.type == COLTYPE_VARCHAR) {*/
            /*DEBUG(DBG_SRCH, "record value for string: %s\n", tval.val.sval);*/
        /*}*/
        if (!record_val_matches(&tval, search_val)) {
            return false;
        }
    }
    return true;
}

static int sort_by_colidx_fn(const void *val1, const void *val2) {
    if (((dbsrchval_t*)val1)->col_idx < ((dbsrchval_t*)val2)->col_idx) {
        return -1;
    } else {
        return 1;
    }
}

static void db_sort_srchvals(struct stordb_tbl *tbl, vec_dbsrchval_t *search_vals) {
    (void)tbl;
    vec_sort(search_vals, sort_by_colidx_fn);
}

static struct stordb_rec *db_find_record(struct stordb *db, const char *tblname, const char *rowvals, dberr_t *dberr) {
    struct stordb_tbl *cur = NULL;
    struct stordb_tbl *tbl = NULL;
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
        return NULL;
    }
    const char *colvalsep = "=";
    const char *valcolsep = ",";
    char *tok = NULL;
    char *in = (char*)rowvals;
    int idx = 0;
    int colidx;
    struct stordb_col *col = NULL;
    vec_dbsrchval_t search_vals;
    vec_init(&search_vals);
    while ((tok = strtok(in, idx % 2 == 0 ? colvalsep : valcolsep)) != NULL) {
        // parse column name
        if (idx % 2 == 0) {
            col = db_colname(tbl, tok, &colidx);
            if (!col) {
                *dberr = DBERR_COLNAME_NOEXIST;
                db_set_lasterr(db, dberr, strndup(tok, STOR_COLNAME_MAX));
                vec_deinit(&search_vals);
                return NULL;
            }
        // parse record value
        } else {
            dbtval_t tval;
            dbsrchval_t srchval;
            dberr_t deser_err;
            int res = db_deserialize_val(db, tok, col->col_type, &tval, NULL, &deser_err);
            if (res == -1) {
                *dberr = deser_err;
                vec_deinit(&search_vals);
                return NULL;
            }
            srchval.tbl_id = tbl->tbl_id;
            srchval.col_id = col->col_id;
            srchval.col_idx = colidx;
            srchval.val = tval.val;
            srchval.type = tval.type;
            vec_push(&search_vals, srchval);
        }
        idx++;
        in = NULL;
    }

    // "col1=val1,col2=", we're missing a value
    if (idx % 2 != 0) {
        *dberr = DBERR_MISSING_FIND_VALUE;
        db_set_lasterr(db, dberr, strndup(col->col_name, STOR_COLNAME_MAX));
        vec_deinit(&search_vals);
        return NULL;
    }

    db_sort_srchvals(tbl, &search_vals);

    // go over blocks and try to find record that matches qualifiers, 1 record at a time... (naive)
    uint16_t blkno;
    int blkidx = 0;
    struct stordb_blk_h *blk;
    struct stordb_rec *found = NULL;
    vec_foreach(&tbl->tbl_blks, blkno, blkidx) {
        blk = db_load_blk(db, blkno);
        ASSERT(blk);
        if (blk->bh_num_records == 0) {
            continue;
        }
        struct stordb_rec *rec;
        int recidx = 0;
        BLK_RECORDS_FOREACH(blk, rec, recidx) {
            DEBUG(DBG_SRCH, "Record %d\n", recidx);
            DEBUG(DBG_SRCH, "  Block record offset: %u\n", blk->bh_record_offsets[recidx]);
            DEBUG(DBG_SRCH, "  Record found, rech_sz=%lu\n", rec->header.rech_sz);
            DEBUG(DBG_SRCH, "  Record found, rec_sz=%lu\n", rec->header.rec_sz);
            /*DEBUG(DBG_SRCH, "  Record found, offset[0]=%ld\n", rec->header.rec_offsets[0]);*/
            /*DEBUG(DBG_SRCH, "  Record found, offset[1]=%ld\n", rec->header.rec_offsets[1]);*/
            if (db_record_matches(rec, &search_vals)) {
                found = rec;
                vec_deinit(&search_vals);
                return found;
            }
        }
    }
    return NULL;
}

static int db_close(struct stordb *db) {
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

int db_init(struct stordb *db) {
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

int main(int argc, char *argv[]) {
    stor_dbgflags = DBG_ALL;

    if (argc <= 2) {
        die("Usage: stor [create|addtbl|addrec|load] dbname [OPTIONS]\n");
    }
    const char *cmd_str = argv[1];
    const char *dbname = argv[2];
    const char *tblname = NULL;
    const char *tblcols = NULL;
    const char *rowvals = NULL;
    enum stor_cmd cmd = CMD_LOAD;
    if (strcmp(cmd_str, "create") == 0) {
        cmd = CMD_CREATE;
    } else if (strcmp(cmd_str, "load") == 0) {
        cmd = CMD_LOAD;
    } else if (strcmp(cmd_str, "addtbl") == 0) {
        cmd = CMD_ADDTBL;
        if (argc != 5) {
            die("Usage: stor addtbl dbname tblname col1:type,col2:type...\n");
        }
        tblname = argv[3];
        tblcols = argv[4];
    } else if (strcmp(cmd_str, "addrec") == 0) {
        cmd = CMD_ADDREC;
        if (argc != 5) {
            die("Usage: stor addrec dbname tblname val1,val2...\n");
        }
        tblname = argv[3];
        rowvals = argv[4];
    } else if (strcmp(cmd_str, "find") == 0) {
        cmd = CMD_FIND;
        if (argc != 5) {
            die("Usage: stor find dbname tblname col1=val,col2=val2...\n");
        }
        tblname = argv[3];
        rowvals = argv[4];
    }
    switch (cmd) {
        case CMD_CREATE:
        case CMD_LOAD:
        case CMD_ADDTBL:
        case CMD_ADDREC:
        case CMD_FIND:
            break;
        default:
            die("Unsupported command: %s\n", cmd_str);
    }
    struct stordb db;
    struct stordb_meta dbmeta;
    memset(&db, 0, sizeof(db));
    memset(&dbmeta, 0, sizeof(dbmeta));
    vec_init(&db.db_blkcache);
    vec_init(&dbmeta.mt_tbls);
    db.db_fname = dbname;
    db.db_meta = dbmeta;
    if (cmd == CMD_CREATE) {
        db.db_meta.mt_magic = STOR_META_MAGIC;
        db.db_mt_dirty = true;
        int res = db_init(&db);
        if (res != 0) {
            die("Couldn't initialize db: %s\n", strerror(errno));
        }
        res = db_flush_meta(&db);
        if (res != 0) {
            die("Couldn't flush db metainfo: %s\n", strerror(errno));
        }
        ASSERT(db_close(&db) == 0);
        return res;
    } else if (cmd == CMD_LOAD) {
        int res = db_load(&db);
        if (res != 0) {
            die("Couldn't load db: %s\n", strerror(errno));
        }
        int num_tbls = db.db_meta.mt_num_tables;
        fprintf(stdout, "DB loaded, %d tables found\n", num_tbls);
        fprintf(stdout, "DB meta (%lu bytes)\n", db.db_meta.mt_sersize);
        if (num_tbls > 0) {
            fprintf(stdout, "Tables:\n");
        }
        for (int i = 0; i < num_tbls; i++) {
            struct stordb_tbl *tbl = db_table(&db, i);
            fprintf(stdout, "  id: %u, name: '%s', cols: %u, #blocks: %u\n",
                    tbl->tbl_id, tbl->tbl_name, tbl->tbl_num_cols, tbl->tbl_num_blks);
            if (tbl->tbl_num_blks > 0) {
                fprintf(stdout, "  blocks: ");
                uint16_t blkno; int bidx;
                vec_foreach(&tbl->tbl_blks, blkno, bidx) {
                    struct stordb_blk_h *blkh = db_load_blk(&db, blkno);
                    ASSERT(blkh);
                    fprintf(stdout, "(%u => %u records) ", blkno, blkh->bh_num_records);
                }
                fprintf(stdout, "\n");
            }
            for (int j = 0; j < tbl->tbl_num_cols; j++) {
                struct stordb_col *col = db_col(tbl, j);
                ASSERT(col);
                fprintf(stdout, "  %s (%s)\n", col->col_name, coltype_str(col->col_type));
            }
        }
        db_close(&db);
        return res;
    } else if (cmd == CMD_ADDTBL) {
        int res = db_load(&db);
        if (res != 0) {
            die("Couldn't load db: %s\n", strerror(errno));
        }
        DEBUG(DBG_SCHEMA, "Loaded DB\n");
        dberr_t dberr;
        int add_tbl_res = db_add_table(&db, tblname, tblcols, &dberr);
        if (add_tbl_res != 0) {
            die("Couldn't add table: %s\n", dbstrerr(dberr));
        }
        db_close(&db);
        return res;
    } else if (cmd == CMD_ADDREC) {
        int res = db_load(&db);
        if (res != 0) {
            die("Couldn't load db: %s\n", strerror(errno));
        }
        DEBUG(DBG_SCHEMA, "Loaded DB\n");
        dberr_t dberr;
        int add_rec_res = db_add_record(&db, tblname, rowvals, &dberr);
        if (add_rec_res == -1) {
            die("Couldn't add record: %s\n", dbstrerr(dberr));
        }
        db_close(&db);
        return res;
    } else if (cmd == CMD_FIND) {
        int res = db_load(&db);
        if (res != 0) {
            die("Couldn't load db: %s\n", strerror(errno));
        }
        DEBUG(DBG_SCHEMA, "Loaded DB\n");
        dberr_t dberr;
        struct stordb_rec *found = NULL;
        found = db_find_record(&db, tblname, rowvals, &dberr);
        if (!found) {
            die("Couldn't find record\n", dbstrerr(dberr));
        } else {
            fprintf(stdout, "Found record\n");
        }
        db_close(&db);
        return res;
    }
    return 1;
}
