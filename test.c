#define STOR_TEST 1
#include "stor.h"
#include "test.h"

int argc;
char **argv;

const char *TEST_DB = "build/testdb.db";
db_t *testdb;

int assertions_passed;
int assertions_failed;
int tests_passed;
int tests_skipped;
int tests_failed;

int test_open_close(void) {
    T_ASSERT_EQ(0, db_open(testdb));
    T_ASSERT_EQ(0, db_close(testdb));
    return 0;
}

int test_addtbl(void) {
    ASSERT(db_open(testdb) == 0);
    const char *tblname = "students";
    const char *tblcols = "id:int,name:varchar";
    dberr_t dberr;
    int old_num_tbls = (int)testdb->db_meta.mt_num_tables;
    unsigned old_num_writes = testdb->db_num_writes;
    int add_tbl_res = db_add_table(testdb, tblname, tblcols, &dberr);
    T_ASSERT_EQ(0, add_tbl_res);
    T_ASSERT_EQ(old_num_tbls+1, (int)testdb->db_meta.mt_num_tables);
    T_ASSERT(old_num_writes < testdb->db_num_writes);
    T_ASSERT(!testdb->db_mt_dirty);
    ASSERT(db_close(testdb) == 0);
    return 0;
}

int test_addrec_flushblk(void) {
    ASSERT(db_open(testdb) == 0);
    const char *tblname = "students";
    const char *rowvals = "1,Mel";
    dberr_t dberr;
    bool flushblk = true;
    unsigned old_num_writes = testdb->db_num_writes;
    int add_rec_res = db_add_record(testdb, tblname, rowvals, NULL, flushblk, &dberr);
    T_ASSERT_EQ(0, add_rec_res);
    T_ASSERT(old_num_writes < testdb->db_num_writes);
    ASSERT(db_close(testdb) == 0);
    return 0;
}

int test_findrec(void) {
    ASSERT(db_open(testdb) == 0);
    const char *tblname = "students";
    const char *srchcrit_str = "id=1"; // exists
    tbl_t *tbl = db_find_table(testdb, tblname);
    T_ASSERT(tbl != NULL);
    vec_dbsrchcrit_t vsearch_crit;
    vec_init(&vsearch_crit);
    dberr_t dberr;
    int res = db_parse_srchcrit(testdb, tbl, srchcrit_str, &vsearch_crit, &dberr);
    T_ASSERT_EQ(0, res);
    T_ASSERT_EQ(1, vsearch_crit.length);
    recinfo_t recinfo;
    memset(&recinfo, 0, sizeof(recinfo));
    res = db_find_record(testdb, tbl, &vsearch_crit, &recinfo, &dberr);
    T_ASSERT_EQ(0, res);
    T_ASSERT(recinfo.rec != NULL);
    T_ASSERT(recinfo.blk != NULL);
    T_ASSERT_EQ(1, *(int*)REC_VALUE_PTR(recinfo.rec,0));
    T_ASSERT(strcmp((char*)REC_VALUE_PTR(recinfo.rec,1), "Mel") == 0);

    vec_clear(&vsearch_crit);
    const char *srchcrit_str2 = "id=1000,name=Mel"; // doesn't exist
    res = db_parse_srchcrit(testdb, tbl, srchcrit_str2, &vsearch_crit, &dberr);
    T_ASSERT_EQ(0, res);
    T_ASSERT_EQ(2, vsearch_crit.length);
    memset(&recinfo, 0, sizeof(recinfo));
    res = db_find_record(testdb, tbl, &vsearch_crit, &recinfo, &dberr);
    T_ASSERT_EQ(0, res);
    T_ASSERT_EQ(NULL, recinfo.rec);
    T_ASSERT_EQ(NULL, recinfo.blk);

    ASSERT(db_close(testdb) == 0);
    return 0;
}

int test_update_single_value_same_size(void) {
    ASSERT(db_open(testdb) == 0);
    const char *tblname = "students";
    const char *srchcrit_str = "name=Mel"; // exists
    const char *updatevals_str = "name=Moo";

    tbl_t *tbl = db_find_table(testdb, tblname);
    vec_dbsrchcrit_t vsearch_crit;
    vec_init(&vsearch_crit);
    dberr_t dberr;
    int res = db_parse_srchcrit(testdb, tbl, srchcrit_str, &vsearch_crit, &dberr);
    T_ASSERT_EQ(0, res);

    vec_dbsrchcrit_t vupdate_info;
    vec_init(&vupdate_info);
    res = db_parse_srchcrit(testdb, tbl, updatevals_str, &vupdate_info, &dberr);
    T_ASSERT_EQ(0, res);

    vec_recinfo_t recinfos;
    vec_init(&recinfos);
    srchopt_t findopts;
    memset(&findopts, 0, sizeof(findopts));
    res = db_find_records(testdb, tbl, &vsearch_crit, &findopts, &recinfos, &dberr);
    T_ASSERT_EQ(0, res);
    T_ASSERT_EQ(1, recinfos.length);
    int num_writes_old = testdb->db_num_writes;
    res = db_update_records(testdb, &recinfos, &vupdate_info, &dberr);
    T_ASSERT_EQ(0, res);
    T_ASSERT(testdb->db_num_writes > num_writes_old);
    int colidx;
    col_t *col = db_find_col(tbl, "name", &colidx);
    T_ASSERT(col);
    rec_t *rec = recinfos.data[0].rec;
    T_ASSERT(rec);
    T_ASSERT(strcmp((char*)REC_VALUE_PTR(rec, colidx), "Moo") == 0);

    ASSERT(db_close(testdb) == 0);
    return 0;
}

int test_move_record(void) {
    ASSERT(db_open(testdb) == 0);
    const char *tblname = "students";
    const char *srchcrit_str = "id=1"; // exists
    tbl_t *tbl = db_find_table(testdb, tblname);
    vec_dbsrchcrit_t vsearch_crit;
    vec_init(&vsearch_crit);
    dberr_t dberr;
    int res = db_parse_srchcrit(testdb, tbl, srchcrit_str, &vsearch_crit, &dberr);
    T_ASSERT_EQ(0, res);
    vec_recinfo_t recinfos;
    vec_init(&recinfos);
    srchopt_t findopts;
    memset(&findopts, 0, sizeof(findopts));
    res = db_find_records(testdb, tbl, &vsearch_crit, &findopts, &recinfos, &dberr);
    T_ASSERT_EQ(0, res);
    T_ASSERT_EQ(1, recinfos.length);

    rec_t *oldrecp = recinfos.data[0].rec;
    rec_t *newrecp = NULL;
    blkh_t *oldblk = recinfos.data[0].blk;
    int oldblk_num_recs = (int)oldblk->bh_num_records;
    blkh_t *newblk = db_alloc_blk(testdb, oldblk->bh_blkno+1, tbl);
    T_ASSERT(newblk);

    res = db_move_record(testdb, oldrecp, oldblk, newblk, &newrecp, &dberr);
    T_ASSERT_EQ(0, res);
    T_ASSERT(newrecp != NULL);
    T_ASSERT(BLK_CONTAINS_REC(newblk, newrecp));
    T_ASSERT(REC_IS_TOMBSTONED(oldrecp));
    T_ASSERT(! BLK_CONTAINS_REC(oldblk, newrecp));
    T_ASSERT_EQ(oldblk_num_recs-1, (int)oldblk->bh_num_records);
    T_ASSERT_EQ(1, (int)newblk->bh_num_records);

    ASSERT(db_close(testdb) == 0);
    return 0;
}

int test_delete(void) {
    ASSERT(db_open(testdb) == 0);
    const char *tblname = "students";
    const char *srchcrit_str = "id=1"; // exists

    tbl_t *tbl = db_find_table(testdb, tblname);
    T_ASSERT(tbl != NULL);

    vec_dbsrchcrit_t vsearch_crit;
    vec_init(&vsearch_crit);
    dberr_t dberr;
    int res = db_parse_srchcrit(testdb, tbl, srchcrit_str, &vsearch_crit, &dberr);
    T_ASSERT_EQ(0, res);
    T_ASSERT_EQ(1, vsearch_crit.length);

    vec_recinfo_t recinfos;
    vec_init(&recinfos);
    srchopt_t findopts;
    memset(&findopts, 0, sizeof(findopts));
    res = db_find_records(testdb, tbl, &vsearch_crit, &findopts, &recinfos, &dberr);
    T_ASSERT_EQ(0, res);
    T_ASSERT_EQ(1, recinfos.length);
    rec_t *rec = recinfos.data[0].rec;
    ASSERT(rec);

    res = db_delete_records(testdb, &recinfos, &dberr);
    T_ASSERT_EQ(0, res);
    T_ASSERT(REC_IS_TOMBSTONED(rec));

    ASSERT(db_close(testdb) == 0);
    return 0;
}

int test_add_lots_of_small_recs(void) {
    int num_recs = 10000;
    ASSERT(db_open(testdb) == 0);
    const char *tblname = "students";
    const char *rowvals = "1,Mel";
    dberr_t dberr;
    bool flushblk = false;
    for (int i = 0; i < num_recs; i++) {
        int add_rec_res = db_add_record(testdb, tblname, rowvals, NULL, flushblk, &dberr);
        ASSERT(add_rec_res == 0);
    }
    T_ASSERT_EQ(0, db_flush_dirty_blks(testdb));

    const char *srchcrit_str = "id=1";
    tbl_t *tbl = db_find_table(testdb, tblname);
    vec_dbsrchcrit_t vsearch_crit;
    vec_init(&vsearch_crit);
    int res = db_parse_srchcrit(testdb, tbl, srchcrit_str, &vsearch_crit, &dberr);
    T_ASSERT_EQ(0, res);
    T_ASSERT_EQ(1, vsearch_crit.length);

    vec_recinfo_t recinfos;
    vec_init(&recinfos);
    vec_reserve(&recinfos, 10000);
    srchopt_t findopts;
    memset(&findopts, 0, sizeof(findopts));
    res = db_find_records(testdb, tbl, &vsearch_crit, &findopts, &recinfos, &dberr);
    T_ASSERT_EQ(0, res);
    T_ASSERT_EQ(10000, recinfos.length);

    res = db_delete_records(testdb, &recinfos, &dberr);
    T_ASSERT_EQ(0, res);

    ASSERT(db_close(testdb) == 0);
    return 0;
}

static void rm_test_db(void) {
    int rm_res = unlink(TEST_DB);
    if (rm_res == -1 && errno != ENOENT) {
        die("error removing old test database: %s\n", strerror(errno));
    }
}

static void init_test_db(db_t *db) {
    rm_test_db();
    memset(db, 0, sizeof(*db));
    memset(&db->db_meta, 0, sizeof(db->db_meta));
    vec_init(&db->db_meta.mt_tbls);
    vec_init(&db->db_blkcache);
    vec_init(&db->db_blksdirty);
    db->db_fname = TEST_DB;
    db->db_meta.mt_magic = STOR_META_MAGIC;
    db->db_mt_dirty = true;
    int res = db_create(db);
    if (res != 0) {
        die("Couldn't create db: %s\n", strerror(errno));
    }
    res = db_flush_meta(db);
    if (res != 0) {
        die("Couldn't flush db metainfo: %s\n", strerror(errno));
    }
    T_ASSERT_EQ(0, db_close(db));
}

int main(int _argc, char **_argv) {
    argc = _argc;
    argv = _argv;

    stor_dbgflags = DBG_ALL;

    struct stordb db;
    struct stordb_meta dbmeta;
    db.db_meta = dbmeta;
    init_test_db(&db);
    testdb = &db;

    START_TESTS();
    RUN_TEST(test_open_close);
    RUN_TEST(test_addtbl);
    RUN_TEST(test_addrec_flushblk);
    RUN_TEST(test_findrec);
    RUN_TEST(test_update_single_value_same_size);
    RUN_TEST(test_move_record);
    RUN_TEST(test_delete);
    SKIP_TEST(test_add_lots_of_small_recs);
    rm_test_db();
    END_TESTS();
    die("unreachable");
}
