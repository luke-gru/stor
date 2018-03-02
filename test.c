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
int tests_failed;

int test_open_close(void) {
    T_ASSERT_EQ(0, db_open(testdb));
    T_ASSERT_EQ(0, db_close(testdb));
    return 0;
}

int test_addtbl(void) {
    T_ASSERT_EQ(0, db_open(testdb));
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
    T_ASSERT_EQ(0, db_close(testdb));
    return 0;
}

int test_addrec_flushblk(void) {
    T_ASSERT_EQ(0, db_open(testdb));
    const char *tblname = "students";
    const char *rowvals = "1,Mel";
    dberr_t dberr;
    bool flushblk = true;
    unsigned old_num_writes = testdb->db_num_writes;
    int add_rec_res = db_add_record(testdb, tblname, rowvals, NULL, flushblk, &dberr);
    T_ASSERT_EQ(0, add_rec_res);
    T_ASSERT(old_num_writes < testdb->db_num_writes);
    T_ASSERT_EQ(0, db_close(testdb));
    return 0;
}

int test_findrec(void) {
    T_ASSERT_EQ(0, db_open(testdb));
    const char *tblname = "students";
    const char *srchcrit_str = "id=1";
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
    T_ASSERT_EQ(0, db_close(testdb));
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
    rm_test_db();
    END_TESTS();
    die("unreachable");
}
