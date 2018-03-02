#include <stor.h>

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
    const char *updatevals_str = NULL;
    const char *srchcrit_str = NULL;
    cmd_t cmd = CMD_LOAD;
    if (strncmp(cmd_str, "create", 10) == 0) {
        cmd = CMD_CREATE;
    } else if (strncmp(cmd_str, "load", 10) == 0) {
        cmd = CMD_LOAD;
    } else if (strncmp(cmd_str, "addtbl", 10) == 0) {
        cmd = CMD_ADDTBL;
        if (argc != 5) {
            die("Usage: stor addtbl dbname tblname col1:type,col2:type...\n");
        }
        tblname = argv[3];
        tblcols = argv[4];
    } else if (strncmp(cmd_str, "addrec", 10) == 0) {
        cmd = CMD_ADDREC;
        if (argc != 5) {
            die("Usage: stor addrec dbname tblname val1,val2...\n");
        }
        tblname = argv[3];
        rowvals = argv[4];
    } else if (strncmp(cmd_str, "find", 10) == 0) {
        cmd = CMD_FIND;
        if (argc != 5) {
            die("Usage: stor find dbname tblname col1=val,col2=val2...\n");
        }
        tblname = argv[3];
        srchcrit_str = argv[4];
    } else if (strncmp(cmd_str, "update", 10) == 0) {
        cmd = CMD_UPDATE;
        if (argc != 7) {
            die("Usage: stor update dbname tblname col1=newval WHERE col1=oldval...\n");
        }
        tblname = argv[3];
        updatevals_str = argv[4];
        srchcrit_str = argv[6];
    } else if (strncmp(cmd_str, "delete", 10) == 0) {
        cmd = CMD_DELETE;
        if (argc != 5) {
            die("Usage: stor delete dbname tblname col1=val...\n");
        }
        tblname = argv[3];
        srchcrit_str = argv[4];
    }
    switch (cmd) {
        case CMD_CREATE:
        case CMD_LOAD:
        case CMD_ADDTBL:
        case CMD_ADDREC:
        case CMD_FIND:
        case CMD_UPDATE:
        case CMD_DELETE:
            break;
        default:
            die("Unsupported command: %s\n", cmd_str);
    }
    struct stordb db;
    struct stordb_meta dbmeta;
    memset(&db, 0, sizeof(db));
    memset(&dbmeta, 0, sizeof(dbmeta));
    vec_init(&db.db_blkcache);
    vec_init(&db.db_blksdirty);
    vec_init(&dbmeta.mt_tbls);
    db.db_fname = dbname;
    db.db_meta = dbmeta;
    if (cmd == CMD_CREATE) {
        db.db_meta.mt_magic = STOR_META_MAGIC;
        db.db_mt_dirty = true;
        int res = db_create(&db);
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
        int res = db_open(&db);
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
            tbl_t *tbl = db_table(&db, i);
            fprintf(stdout, "  id: %u, name: '%s', cols: %u, #blocks: %u\n",
                    tbl->tbl_id, tbl->tbl_name, tbl->tbl_num_cols, tbl->tbl_num_blks);
            if (tbl->tbl_num_blks > 0) {
                fprintf(stdout, "  blocks: ");
                uint16_t blkno; int bidx;
                vec_foreach(&tbl->tbl_blks, blkno, bidx) {
                    blkh_t *blkh = db_load_blk(&db, blkno);
                    ASSERT(blkh);
                    fprintf(stdout, "(%u => %u records) ", blkno, blkh->bh_num_records);
                }
                fprintf(stdout, "\n");
            }
            for (int j = 0; j < tbl->tbl_num_cols; j++) {
                col_t *col = db_col(tbl, j);
                ASSERT(col);
                fprintf(stdout, "  %s (%s)\n", col->col_name, coltype_str(col->col_type));
            }
        }
        db_close(&db);
        return res;
    } else if (cmd == CMD_ADDTBL) {
        int res = db_open(&db);
        if (res != 0) {
            die("Couldn't load db: %s\n", strerror(errno));
        }
        DEBUG(DBG_STATE, "Loaded DB\n");
        dberr_t dberr;
        int add_tbl_res = db_add_table(&db, tblname, tblcols, &dberr);
        if (add_tbl_res != 0) {
            die("Couldn't add table: %s\n", dbstrerr(dberr));
        }
        db_close(&db);
        return res;
    } else if (cmd == CMD_ADDREC) {
        int res = db_open(&db);
        if (res != 0) {
            die("Couldn't load db: %s\n", strerror(errno));
        }
        DEBUG(DBG_STATE, "Loaded DB\n");
        dberr_t dberr;
        int add_rec_res = db_add_record(&db, tblname, rowvals, NULL, true, &dberr);
        if (add_rec_res == -1) {
            die("Couldn't add record: %s\n", dbstrerr(dberr));
        }
        db_close(&db);
        return res;
    } else if (cmd == CMD_FIND) {
        int res = db_open(&db);
        if (res != 0) {
            die("Couldn't load db: %s\n", strerror(errno));
        }
        DEBUG(DBG_STATE, "Loaded DB\n");
        dberr_t dberr;
        recinfo_t recinfo;
        memset(&recinfo, 0, sizeof(recinfo));
        tbl_t *tbl = db_find_table(&db, tblname);
        if (!tbl) {
            die("Couldn't find table: %s\n", tblname);
        }
        vec_dbsrchcrit_t vsearch_crit;
        vec_init(&vsearch_crit);
        res = db_parse_srchcrit(&db, tbl, srchcrit_str, &vsearch_crit, &dberr);
        if (res != 0) {
            die("Error parsing search criteria: %s\n", dbstrerr(dberr));
        }
        res = db_find_record(&db, tbl, &vsearch_crit, &recinfo, &dberr);
        if (res != 0) {
            die("Error searching for record: %s", dbstrerr(dberr));
        }
        rec_t *found = recinfo.rec;
        if (!found) {
            fprintf(stderr, "Couldn't find record\n");
        } else {
            fprintf(stdout, "Found record\n");
        }
        db_close(&db);
        return (found ? 0 : 1);
    } else if (cmd == CMD_UPDATE) {
        int res = db_open(&db);
        if (res != 0) {
            die("Couldn't load db: %s\n", strerror(errno));
        }
        DEBUG(DBG_STATE, "Loaded DB\n");
        dberr_t dberr;
        tbl_t *tbl = db_find_table(&db, tblname);
        if (!tbl) {
            die("Couldn't find table: %s\n", tblname);
        }

        vec_dbsrchcrit_t vsearch_crit;
        vec_init(&vsearch_crit);
        res = db_parse_srchcrit(&db, tbl, srchcrit_str, &vsearch_crit, &dberr);
        if (res != 0) {
            die("Error parsing search criteria: %s\n", dbstrerr(dberr));
        }

        vec_dbsrchcrit_t vupdate_info;
        vec_init(&vupdate_info);
        res = db_parse_srchcrit(&db, tbl, updatevals_str, &vupdate_info, &dberr);
        if (res != 0) {
            die("Error parsing update info: %s\n", dbstrerr(dberr));
        }

        vec_recinfo_t recinfos;
        vec_init(&recinfos);
        srchopt_t findopts;
        memset(&findopts, 0, sizeof(findopts));
        res = db_find_records(&db, tbl, &vsearch_crit, &findopts, &recinfos, &dberr);

        if (res != 0) {
            die("Error searching for records: %s", dbstrerr(dberr));
        }
        if (recinfos.length == 0) {
            fprintf(stderr, "No records matched criteria\n");
            db_close(&db);
            return 1;
        }
        DEBUG(DBG_UPDATE, "Updating %d records\n", recinfos.length);
        res = db_update_records(&db, &recinfos, &vupdate_info, &dberr);
        if (res != 0) {
            die("Error updating records: %s", dbstrerr(dberr));
        }
        db_close(&db);
        return 0;
    } else if (cmd == CMD_DELETE) {
        int res = db_open(&db);
        if (res != 0) {
            die("Couldn't load db: %s\n", strerror(errno));
        }
        DEBUG(DBG_STATE, "Loaded DB\n");
        dberr_t dberr;
        tbl_t *tbl = db_find_table(&db, tblname);
        if (!tbl) {
            die("Couldn't find table: %s\n", tblname);
        }

        vec_dbsrchcrit_t vsearch_crit;
        vec_init(&vsearch_crit);
        res = db_parse_srchcrit(&db, tbl, srchcrit_str, &vsearch_crit, &dberr);
        if (res != 0) {
            die("Error parsing search criteria: %s\n", dbstrerr(dberr));
        }
        vec_recinfo_t recinfos;
        vec_init(&recinfos);
        srchopt_t findopts;
        memset(&findopts, 0, sizeof(findopts));
        res = db_find_records(&db, tbl, &vsearch_crit, &findopts, &recinfos, &dberr);

        if (res != 0) {
            die("Error searching for records: %s", dbstrerr(dberr));
        }
        if (recinfos.length == 0) {
            fprintf(stderr, "No records matched criteria\n");
            db_close(&db);
            return 1;
        }
        DEBUG(DBG_DEL, "Deleting %d records\n", recinfos.length);
        res = db_delete_records(&db, &recinfos, &dberr);
        if (res != 0) {
            die("Error deleting records: %s", dbstrerr(dberr));
        }
        fprintf(stdout, "Successfully deleted %d records\n", recinfos.length);
        db_close(&db);
        return 0;
    }
    return 1;
}
