#define STOR_TEST 1
#include "stor.h"
#include "test.h"

int argc;
char **argv;

const char *TEST_DB = "build/testdb.db";
db_t *testdb;
dberr_t *testerr;

static qcoltype_t *QCOLTYPE_VARCHAR_DEFAULT;

int assertions_passed;
int assertions_failed;
int tests_passed;
int tests_skipped;
int tests_failed;

// helper functions
static blkh_t *alloc_empty_mem_blk(uint16_t blkno, tbl_t *tbl) {
    blkh_t *blk = malloc(STOR_PAGESZ);
    ASSERT_MEM(blk);
    memset(blk, 0, STOR_PAGESZ);
    blk->bh_magic = STOR_BLKH_MAGIC;
    blk->bh_blkno = blkno;
    blk->bh_tbl_id = tbl->tbl_id;
    blk->bh_free = STOR_PAGESZ-sizeof(*blk);
    blk->bh_num_records = 0;

    blkinfo_t blkinfo;
    blkinfo.blk = blk;
    vec_init(&blkinfo.blk_holes);
    blkinfo.holes_computed = false;
    blkinfo.is_dirty = false;
    vec_push(&testdb->db_vblkinfo, blkinfo);
    return blk;
}

static rec_t *blk_enter_fake_rec(blkh_t *blk, tbl_t *tbl, uint16_t rec_offset, size_t recsize) {
    // NOTE: recsize includes record header size and record size
    ASSERT(recsize > sizeof(rech_t));
    ASSERT(rec_offset >= sizeof(blkh_t) && rec_offset < STOR_PAGESZ);
    ASSERT(rec_offset+recsize <= STOR_PAGESZ);
    ASSERT(blk->bh_tbl_id = tbl->tbl_id);
    memset(PTR(blk)+rec_offset, 0, recsize);
    rec_t *rec = (rec_t*)(PTR(blk)+rec_offset);
    rec->header.rech_sz = sizeof(rech_t);
    rec->header.rec_sz = recsize-sizeof(rech_t);
    blk->bh_num_records++;
    blk->bh_record_offsets[blk->bh_num_records-1] = rec_offset;
    blk->bh_free -= (recsize+sizeof(uint16_t));
    blk_mark_hole_filled(testdb, blk, NULL, rec_offset, rec_offset+recsize);
    return rec;
}

static rec_t *blk_alloc_fake_rec(tbl_t *tbl, size_t recsz) {
    size_t rech_sz = sizeof(rech_t)+(sizeof(off_t)*tbl->tbl_num_cols);
    size_t recsz_total = recsz+rech_sz;
    ASSERT(recsz_total <= STOR_PAGESZ);
    rec_t *newrec = malloc(recsz_total);
    ASSERT_MEM(newrec);
    memset(newrec, 0, recsz_total);
    newrec->header.rech_sz = rech_sz;
    newrec->header.rec_sz = recsz;
    return newrec;
}

static void empty_mem_blk(blkh_t *blk) {
    blk->bh_num_records = 0;
    blk->bh_free = BLK_FREE_INITIAL;
}

// tests begin
int test_open_close(void) {
    T_ASSERT_EQ(0, db_open(testdb, testerr));
    T_ASSERT_EQ(0, db_close(testdb, testerr));
cleanup:
    return 0;
}

int test_addtbl(void) {
    ASSERT(db_open(testdb, testerr) == 0);
    const char *tblname = "students";
    const char *tblcols = "id:int,name:varchar";
    dberr_t dberr;
    int old_num_tbls = (int)testdb->db_meta.mt_num_tables;
    unsigned old_num_writes = testdb->db_num_writes;
    int add_tbl_res = db_add_table(testdb, tblname, tblcols, true, &dberr);
    T_ASSERT_EQ(0, add_tbl_res);
    T_ASSERT_EQ(old_num_tbls+1, (int)testdb->db_meta.mt_num_tables);
    T_ASSERT(old_num_writes < testdb->db_num_writes);
    T_ASSERT(!testdb->db_mt_dirty);

cleanup:
    ASSERT(db_close(testdb, testerr) == 0);
    return 0;
}

int test_addrec_flushblk(void) {
    ASSERT(db_open(testdb, testerr) == 0);
    const char *tblname = "students";
    const char *rowvals = "1,Mel";
    dberr_t dberr;
    bool flushblk = true;
    unsigned old_num_writes = testdb->db_num_writes;
    int add_rec_res = db_add_record(testdb, tblname, rowvals, NULL, flushblk, &dberr);
    T_ASSERT_EQ(0, add_rec_res);
    T_ASSERT(old_num_writes < testdb->db_num_writes);

cleanup:
    ASSERT(db_close(testdb, testerr) == 0);
    return 0;
}

int test_findrec(void) {
    ASSERT(db_open(testdb, testerr) == 0);
    const char *tblname = "students";
    const char *srchcrit_str = "id=1"; // exists
    tbl_t *tbl = db_table_from_name(testdb, tblname);
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

cleanup:
    ASSERT(db_close(testdb, testerr) == 0);
    return 0;
}

int test_update_single_value_same_size(void) {
    ASSERT(db_open(testdb, testerr) == 0);
    const char *tblname = "students";
    const char *srchcrit_str = "name=Mel"; // exists
    const char *updatevals_str = "name=Moo";

    tbl_t *tbl = db_table_from_name(testdb, tblname);
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
    col_t *col = db_col_from_name(tbl, "name", &colidx);
    T_ASSERT(col);
    rec_t *rec = recinfos.data[0].rec;
    T_ASSERT(rec);
    T_ASSERT(strcmp((char*)REC_VALUE_PTR(rec, colidx), "Moo") == 0);

cleanup:
    ASSERT(db_close(testdb, testerr) == 0);
    return 0;
}

int test_move_record(void) {
    ASSERT(db_open(testdb, testerr) == 0);
    const char *tblname = "students";
    const char *srchcrit_str = "id=1"; // exists
    tbl_t *tbl = db_table_from_name(testdb, tblname);
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
    blkh_t *newblk = db_alloc_blk(testdb, oldblk->bh_blkno+1, tbl, false, &dberr);
    T_ASSERT(newblk);

    res = db_move_record_to_blk(testdb, oldrecp, oldblk, newblk, 0, &newrecp, &dberr);
    T_ASSERT_EQ(0, res);
    T_ASSERT(newrecp != NULL);
    T_ASSERT(BLK_CONTAINS_REC(newblk, newrecp));
    T_ASSERT(REC_IS_TOMBSTONED(oldrecp));
    T_ASSERT(! BLK_CONTAINS_REC(oldblk, newrecp));
    T_ASSERT_EQ(oldblk_num_recs-1, (int)oldblk->bh_num_records);
    T_ASSERT_EQ(1, (int)newblk->bh_num_records);

cleanup:
    ASSERT(db_close(testdb, testerr) == 0);
    return 0;
}

int test_update_single_value_diff_size_move_up(void) {
    ASSERT(db_open(testdb, testerr) == 0);
    const char *tblname = "students";
    const char *srchcrit_str = "name=Moo"; // exists
    const char *updatevals_str = "name=somebiggervalue";

    tbl_t *tbl = db_table_from_name(testdb, tblname);
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
    res = db_update_records(testdb, &recinfos, &vupdate_info, &dberr);
    T_ASSERT_EQ(0, res);
    int colidx;
    col_t *col = db_col_from_name(tbl, "name", &colidx);
    T_ASSERT(col);
    rec_t *rec = recinfos.data[0].rec;
    T_ASSERT(rec);
    T_ASSERT(strcmp((char*)REC_VALUE_PTR(rec, colidx), "somebiggervalue") == 0);

cleanup:
    ASSERT(db_close(testdb, testerr) == 0);
    return 0;
}

int test_update_single_value_diff_size_grow_down(void) {
    ASSERT(db_open(testdb, testerr) == 0);
    const char *tblname = "tweets";
    const char *tblcols_str = "id:int,retweets:int,tweet:varchar";
    const char *updatevals_str = "tweet=A much longer tweet...abcdefg";
    dberr_t dberr;
    int res = db_add_table(testdb, tblname, tblcols_str, true, &dberr);
    ASSERT(res == 0);
    tbl_t *tbl = db_table_from_name(testdb, tblname);
    blkh_t *blk = NULL;
    char *rowvals_str = kstrdup("1,5,my first tweet!");
    int num_recs = 5;
    for (int i = 0; i < num_recs; i++) {
        rowvals_str[0] = (i+1)+'0';
        bool flushblk = true;
        res = db_add_record(testdb, tblname, rowvals_str, &blk, flushblk, &dberr);
        ASSERT(res == 0);
    }
    T_ASSERT_EQ(num_recs, blk->bh_num_records);
    T_ASSERT(blk);
    rec_t *top_rec = BLK_LAST_REC(blk);
    T_ASSERT(top_rec);
    rec_t *under_top_rec = BLK_NTH_REC(blk, 3);
    T_ASSERT(under_top_rec);
    DEBUG(DBG_TEST, "POINTERS: %p, %p\n", PTR(top_rec)+REC_SZ(top_rec), PTR(under_top_rec));
    T_ASSERT(PTR(top_rec)+REC_SZ(top_rec) == PTR(under_top_rec));

    // delete record under the top rec so that the top rec grows down when we
    // update its varchar value.
    vec_recinfo_t vrecinfo;
    vec_init(&vrecinfo);
    recinfo_t recinfo = {
        .blk = blk,
        .rec = under_top_rec,
    };
    vec_push(&vrecinfo, recinfo);
    res = db_delete_records(testdb, &vrecinfo, &dberr);
    T_ASSERT_EQ(0, res);
    T_ASSERT(REC_IS_TOMBSTONED(under_top_rec));

    vec_clear(&vrecinfo);
    recinfo.rec = top_rec;
    vec_push(&vrecinfo, recinfo);

    vec_dbsrchcrit_t vupdate_info;
    vec_init(&vupdate_info);
    res = db_parse_srchcrit(testdb, tbl, updatevals_str, &vupdate_info, &dberr);
    T_ASSERT_EQ(0, res);

    res = db_update_records(testdb, &vrecinfo, &vupdate_info, &dberr);
    T_ASSERT_EQ(0, res);
    ASSERT(! REC_IS_TOMBSTONED(top_rec));
    DEBUG(DBG_TEST, "New tweet value: %s\n", (char*)REC_VALUE_PTR(top_rec,2));
    T_ASSERT(strcmp((char*)REC_VALUE_PTR(top_rec,2), "A much longer tweet...abcdefg") == 0);

cleanup:
    ASSERT(db_close(testdb, testerr) == 0);
    return 0;
}

// To fill up the block with some records, which starts at the bottom of the
// block, and then update the bottom-most value with a bigger value. This
// forces us to find a hole not directly above or below the record.
int test_update_single_value_diff_size_move_same_block(void) {
    ASSERT(db_open(testdb, testerr) == 0);
    const char *tblname = "restos";
    const char *tblcols_str = "num_stars:int,name:varchar";
    dberr_t dberr;
    int res = db_add_table(testdb, tblname, tblcols_str, true, &dberr);
    ASSERT(res == 0);
    tbl_t *tbl = db_table_from_name(testdb, tblname);
    const char *rowvals_str = "5,Fung Shing";
    int num_recs = 5;
    blkh_t *blk = NULL;
    for (int i = 0; i < num_recs; i++) {
        res = db_add_record(testdb, tblname, rowvals_str, &blk, true, &dberr);
        ASSERT(res == 0);
    }
    T_ASSERT(blk);
    T_ASSERT_EQ(num_recs, blk->bh_num_records);
    rec_t *rec_btm = BLK_FIRST_REC(blk);
    T_ASSERT(rec_btm);
    rec_t *rec_top = BLK_LAST_REC(blk);
    T_ASSERT(PTR(rec_top) < PTR(rec_btm));

    vec_blkdata_t vblkholes;
    vec_init(&vblkholes);
    bool force_hole_recompute = true;
    blk_find_holes(testdb, blk, &vblkholes, force_hole_recompute);
    T_ASSERT_EQ(1, vblkholes.length);
    DEBUG(DBG_TEST, "bh_free: %u, hole datasz: %u, hole offset: %u\n", blk->bh_free,
            vblkholes.data[0].datasz, vblkholes.data[0].blkoff);
    T_ASSERT_EQ(blk->bh_free, vblkholes.data[0].datasz);
    T_ASSERT_EQ((uint16_t)BLKH_SIZE(blk), vblkholes.data[0].blkoff);

    vec_recinfo_t recinfos;
    vec_init(&recinfos);
    recinfo_t recinfo;
    recinfo.blk = blk;
    recinfo.rec = rec_btm;
    vec_push(&recinfos, recinfo);

    const char *updatevals_str = "name=The Greatest Restaurant in the World";
    vec_dbsrchcrit_t vupdate_info;
    vec_init(&vupdate_info);
    res = db_parse_srchcrit(testdb, tbl, updatevals_str, &vupdate_info, &dberr);
    T_ASSERT_EQ(0, res);

    res = db_update_records(testdb, &recinfos, &vupdate_info, &dberr);
    T_ASSERT_EQ(0, res);
    rec_t *updated_rec = BLK_FIRST_REC(blk);
    T_ASSERT(updated_rec != rec_btm);
    T_ASSERT(strcmp((char*)REC_VALUE_PTR(updated_rec, 1),
        "The Greatest Restaurant in the World") == 0);

cleanup:
    ASSERT(db_close(testdb, testerr) == 0);
    return 0;
}

int test_update_single_value_diff_size_move_diff_block(void) {
    ASSERT(db_open(testdb, testerr) == 0);

    const char *tblname = "films";
    const char *tblcols_str = "name:varchar,year:int";
    const char *longfilmname = "Night of the Day of the Dawn of the Son of the Bride of the Return of the Revenge of the Terror of the Attack of the Evil Mutant Hellbound Flesh-Eating Subhumanoid Zombified Living Dead Part 3";
    const char *updatevals_str = "name=Night of the Day of the Dawn of the Son of the Bride of the Return of the Revenge of the Terror of the Attack of the Evil Mutant Hellbound Flesh-Eating Subhumanoid Zombified Living Dead Part 3";
    dberr_t dberr;
    int res = db_add_table(testdb, tblname, tblcols_str, true, &dberr);
    ASSERT(res == 0);
    tbl_t *tbl = db_table_from_name(testdb, tblname);
    blkh_t *blk = NULL;
    blkh_t *blkfirstrec = NULL;
    char *rowvals_str = kstrdup("Predator,1987");
    int num_recs = 5;
    size_t recsz;
    for (int i = 0; i < num_recs; i++) {
        res = db_add_record(testdb, tblname, rowvals_str, &blk, true, &dberr);
        ASSERT(res == 0);
        if (i == 0) {
            blkfirstrec = blk;
            rec_t *rec = BLK_LAST_REC(blk);
            ASSERT(rec);
            recsz = REC_SZ(rec);
            num_recs = (blk->bh_free / recsz)-3;
            DEBUG(DBG_TEST, "Changing num_recs iterations from 5 to %d\n", num_recs);
        }
    }
    T_ASSERT_EQ(blk, blkfirstrec);
    DEBUG(DBG_TEST, "blk free size after %d insertions: %u\n", num_recs, blk->bh_free);
    rec_t *top_rec = BLK_LAST_REC(blk);

    // delete record under the top rec so that the top rec grows down when we
    // update its varchar value.
    vec_recinfo_t vrecinfo;
    vec_init(&vrecinfo);
    recinfo_t recinfo = {
        .blk = blk,
        .rec = top_rec,
    };
    vec_push(&vrecinfo, recinfo);

    vec_dbsrchcrit_t vupdate_info;
    vec_init(&vupdate_info);
    res = db_parse_srchcrit(testdb, tbl, updatevals_str, &vupdate_info, &dberr);
    db_log_lasterr(testdb);
    T_ASSERT_EQ(0, res);
    char *dbval = DBVAL_PTR(&vupdate_info.data[0].val, QCOLTYPE_VARCHAR_DEFAULT->type);
    T_ASSERT_EQ(0, strcmp(longfilmname, dbval));
    T_ASSERT_EQ(strlen(longfilmname)+1, DBVAL_SZ(&vupdate_info.data[0].val, QCOLTYPE_VARCHAR_DEFAULT));

    res = db_update_records(testdb, &vrecinfo, &vupdate_info, &dberr);
    T_ASSERT_EQ(0, res);
    ASSERT(REC_IS_TOMBSTONED(top_rec));
    rec_t *newrec = vrecinfo.data[0].rec;
    blkh_t *newblk = vrecinfo.data[0].blk;
    T_ASSERT(newrec != top_rec);
    T_ASSERT(newblk != blk);
    char *newdbval = (char*)REC_VALUE_PTR(newrec,0);
    T_ASSERT(strcmp(newdbval, longfilmname) == 0);

cleanup:
    ASSERT(db_close(testdb, testerr) == 0);
    return 0;
}

int test_delete(void) {
    ASSERT(db_open(testdb, testerr) == 0);
    const char *tblname = "students";
    const char *srchcrit_str = "id=1"; // exists

    tbl_t *tbl = db_table_from_name(testdb, tblname);
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

cleanup:
    ASSERT(db_close(testdb, testerr) == 0);
    return 0;
}

int test_add_lots_of_small_recs(void) {
    int num_recs = 10000;
    ASSERT(db_open(testdb, testerr) == 0);
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
    tbl_t *tbl = db_table_from_name(testdb, tblname);
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

cleanup:
    ASSERT(db_close(testdb, testerr) == 0);
    return 0;
}

int test_blk_mark_hole_filled(void) {
    ASSERT(db_open(testdb, testerr) == 0);

    vec_deinit(&testdb->db_vblkinfo);
    vec_clear(&testdb->db_vblkinfo);

    blkh_t *random_blk = vec_last(&testdb->db_blkcache);
    ASSERT(random_blk);
    blkdata_t hole1;
    hole1.blk = random_blk;
    hole1.blkoff = 10;
    hole1.datasz = 100;
    vec_blkdata_t vholes;
    vec_init(&vholes);
    vec_push(&vholes, hole1);

    // fill 1 hole exactly
    blk_mark_hole_filled(testdb, random_blk, &vholes, 10, 110);
    T_ASSERT_EQ(0, vholes.length);

    hole1.blkoff = 10;
    hole1.datasz = 100;
    vec_push(&vholes, hole1);
    // fill part of 1 hole (10,110) with (15,25), new holes: (10,14),(26,110)
    blk_mark_hole_filled(testdb, random_blk, &vholes, 15, 25);
    T_ASSERT_EQ(2, vholes.length);
    T_ASSERT_EQ(10, vholes.data[0].blkoff);
    T_ASSERT_EQ(4, vholes.data[0].datasz);
    T_ASSERT_EQ(26, vholes.data[1].blkoff);
    T_ASSERT_EQ(84, vholes.data[1].datasz);

    // fill top of hole
    hole1.blkoff = 10;
    hole1.datasz = 100;
    vec_deinit(&vholes);
    vec_push(&vholes, hole1);
    blk_mark_hole_filled(testdb, random_blk, &vholes, 10, 25);
    T_ASSERT_EQ(1, vholes.length);
    T_ASSERT_EQ(26, vholes.data[0].blkoff);
    T_ASSERT_EQ(84, vholes.data[0].datasz);

    // fill bottom of hole, (10,110) with (90,110), new data: (10,89)
    hole1.blkoff = 10;
    hole1.datasz = 100;
    vec_deinit(&vholes);
    vec_push(&vholes, hole1);
    blk_mark_hole_filled(testdb, random_blk, &vholes, 90, 110);
    T_ASSERT_EQ(1, vholes.length);
    T_ASSERT_EQ(10, vholes.data[0].blkoff);
    T_ASSERT_EQ(79, vholes.data[0].datasz);

cleanup:
    ASSERT(db_close(testdb, testerr) == 0);
    return 0;
}


int test_blk_find_holes(void) {
    ASSERT(db_open(testdb, testerr) == 0);
    vec_deinit(&testdb->db_vblkinfo);
    vec_clear(&testdb->db_vblkinfo);

    tbl_t *tbl = db_table_from_name(testdb, "students");
    ASSERT(tbl);
    blkh_t *blk = alloc_empty_mem_blk(100, tbl);

    vec_blkdata_t vholes;
    vec_init(&vholes);
    bool force_recompute = true;
    // no records = 1 big hole
    blk_find_holes(testdb, blk, &vholes, force_recompute);
    T_ASSERT_EQ(1, vholes.length);
    T_ASSERT_EQ(sizeof(blkh_t)+sizeof(uint16_t), vholes.data[0].blkoff);
    T_ASSERT_EQ(STOR_PAGESZ-sizeof(blkh_t)-sizeof(uint16_t), vholes.data[0].datasz);

    // should create a hole at (sizeof(blkh_t),+9),(sizeof(blkh_t)+110,4096-sizeof(blkh_t))
    rec_t *newrec = blk_enter_fake_rec(blk, tbl, sizeof(blkh_t)+12, 100);
    ASSERT(newrec);
    ASSERT(REC_SZ(newrec) == 100);

    vec_clear(&vholes);
    vec_deinit(&vholes);
    blk_find_holes(testdb, blk, &vholes, force_recompute);
    DEBUG(DBG_TEST, "sizeof(blkh_t): %lu, holes found: %d hole1: (offset: %u, size: %u)\n",
            sizeof(blkh_t), vholes.length, vholes.data[0].blkoff, vholes.data[0].datasz);
    T_ASSERT_EQ(2, vholes.length);
    T_ASSERT_EQ(sizeof(blkh_t)+2, vholes.data[0].blkoff);
    T_ASSERT_EQ(10, vholes.data[0].datasz);
    T_ASSERT_EQ(112+sizeof(blkh_t), vholes.data[1].blkoff);
    T_ASSERT_EQ(STOR_PAGESZ-sizeof(blkh_t)-112, vholes.data[1].datasz);

cleanup:
    if (blk) free(blk);
    ASSERT(db_close(testdb, testerr) == 0);
    return 0;
}

int test_db_blk_cpy_rec(void) {
    ASSERT(db_open(testdb, testerr) == 0);

    tbl_t *tbl = db_table_from_name(testdb, "students");
    ASSERT(tbl);
    blkh_t *blk = alloc_empty_mem_blk(101, tbl);
    rec_t *bigrec = blk_alloc_fake_rec(tbl, 1000);
    size_t recsz = REC_SZ(bigrec);
    rec_t *recout = NULL;
    // pass 0 for blk_off, should find empty space at end of record
    int res = db_blk_cpy_rec(testdb, blk, bigrec, 0, &recout);
    T_ASSERT_EQ(0, res);
    T_ASSERT(recout != NULL);
    T_ASSERT(BLK_CONTAINS_REC(blk, recout));
    T_ASSERT_EQ(recsz, REC_SZ(recout));
    T_ASSERT_EQ(PTR(recout), BLK_END(blk)-recsz);

    empty_mem_blk(blk);
    // pass 50 for blk_off, should cpy record to that location
    recout = NULL;
    uint16_t blk_offset = 50;
    res = db_blk_cpy_rec(testdb, blk, bigrec, blk_offset, &recout);
    T_ASSERT_EQ(0, res);
    T_ASSERT(BLK_CONTAINS_REC(blk, recout));
    T_ASSERT_EQ(recsz, REC_SZ(recout));
    T_ASSERT_EQ(PTR(recout), PTR(blk)+blk_offset);


cleanup:
    if (blk) free(blk);
    if (bigrec) free(bigrec);
    ASSERT(db_close(testdb, testerr) == 0);
    return 0;
}

int test_varchar_value_bigger_than_255_chars(void) {
    ASSERT(db_open(testdb, testerr) == 0);

    const char *tblname = "computers";
    const char *tblcols_str = "id:int,brand:varchar(1024)";
    dberr_t dberr;
    int res = db_add_table(testdb, tblname, tblcols_str, true, &dberr);
    db_log_lasterr(testdb);
    ASSERT(res == 0);
    tbl_t *tbl = db_table_from_name(testdb, tblname);
    ASSERT(tbl);

    char *large_brand = malloc(1024);
    ASSERT_MEM(large_brand);
    memset(large_brand, 'a', 1023);
    large_brand[1023] = '\0';

    char *rowvals_str = malloc(1024+2);
    ASSERT_MEM(rowvals_str);
    memcpy(rowvals_str, (char*)"1,", 2);
    memcpy(rowvals_str+2, large_brand, 1024);
    blkh_t *blk = NULL;
    int add_rec_res = db_add_record(testdb, tblname, rowvals_str, &blk, true, &dberr);
    T_ASSERT_EQ(0, add_rec_res);
    T_ASSERT(blk != NULL);
    rec_t *rec = BLK_LAST_REC(blk);
    T_ASSERT(BLK_CONTAINS_REC(blk, rec));
    T_ASSERT(strcmp(large_brand, (char*)REC_VALUE_PTR(rec,1)) == 0);

cleanup:
    if (large_brand) free(large_brand);
    if (rowvals_str) free(rowvals_str);
    ASSERT(db_close(testdb, testerr) == 0);
    return 0;
}

int test_db_next_blkno(void) {
    ASSERT(db_open(testdb, testerr) == 0);
    const char *tblname = "computers";
    tbl_t *tbl = db_table_from_name(testdb, tblname);
    ASSERT(tbl);
    dberr_t dberr = 0;
    off_t saved_offset = testdb->db_offset;
    uint16_t next_blkno = db_next_blkno(testdb, &dberr);
    DEBUG(DBG_TEST, "next blkno: %u\n", next_blkno);
    T_ASSERT(next_blkno > 0);
    T_ASSERT_EQ(saved_offset, testdb->db_offset);
    T_ASSERT_EQ(dberr, 0);
    blkh_t *newblk = db_alloc_blk(testdb, next_blkno, tbl, true, &dberr);
    T_ASSERT(newblk);
    uint16_t next_blkno2 = db_next_blkno(testdb, &dberr);
    DEBUG(DBG_TEST, "next blkno2: %u\n", next_blkno2);
    T_ASSERT_EQ(next_blkno2, next_blkno+1);
    T_ASSERT_EQ(dberr, 0);
cleanup:
    ASSERT(db_close(testdb, testerr) == 0);
    return 0;
}

int test_metainfo_can_be_larger_than_1_page(void) {
    // insert lots of tables so the serialized metainfo is larger than 1 block (page)
    ASSERT(db_open(testdb, testerr) == 0);
    char tblname_prefix[STOR_TBLNAME_MAX-4];
    memset(tblname_prefix, 'a', sizeof(tblname_prefix));
    char tblname[STOR_TBLNAME_MAX];
    memset(tblname, 0, sizeof(tblname));
    strncpy(tblname, tblname_prefix, sizeof(tblname_prefix));
    const char *colinfo_str = "id:int,string:varchar";
    int num_tables = 200;
    char num_buf[4] = {0};
    ASSERT(200*STOR_TBLNAME_MAX > STOR_PAGESZ);
    dberr_t dberr;
    vec_str_t vtblnames;
    vec_init(&vtblnames);
    int res;
    for (int i = 0; i < num_tables; i++) {
        memset(tblname+sizeof(tblname_prefix), 0, 4);
        memset(num_buf, 0, 3);
        snprintf(num_buf, 4, "%03d", i);
        strncat(tblname, num_buf, 3);
        vec_push(&vtblnames, kstrdup(tblname));
        res = db_add_table(testdb, tblname, colinfo_str, false, &dberr);
        db_log_lasterr(testdb);
        T_ASSERT_EQ(0, res);
    }
    res = db_flush_meta(testdb, &dberr);
    T_ASSERT_EQ(0, res);
    T_ASSERT_EQ(0, db_close(testdb, testerr));
    // load meta info
    T_ASSERT_EQ(0, db_open(testdb, testerr));

    int i = 0;
    char *cur_tblname = NULL;
cleanup:
    vec_foreach(&vtblnames, cur_tblname, i) {
        tbl_t *tbl = db_table_from_name(testdb, cur_tblname);
        ASSERT(tbl);
        bool clear_blks = true;
        bool flushtodisk = false; // we do a bulk flush after dropping all the tables, below
        int drop_res = db_drop_table(testdb, tbl, clear_blks, flushtodisk, &dberr);
        T_ASSERT_EQ(0, drop_res);
        free(tbl);
    }
    T_ASSERT_EQ(0, db_flush_meta(testdb, &dberr));
    vec_deinit(&vtblnames);
    ASSERT(db_close(testdb, testerr) == 0);
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
    vec_init(&db->db_vblkinfo);
    db->db_fname = TEST_DB;
    db->db_meta.mt_magic = STOR_META_MAGIC;
    db->db_mt_dirty = true;
    int res = db_create(db, testerr);
    if (res != 0) {
        die("Couldn't create db: %s\n", strerror(errno));
    }
    dberr_t dberr = 0;
    res = db_flush_meta(db, &dberr);
    if (res != 0) {
        die("Couldn't flush db metainfo: %s\n", dbstrerr(dberr));
    }
    T_ASSERT_EQ(0, db_close(db, testerr));
    //db->db_mem_only = true;
}

int main(int _argc, char **_argv) {
    argc = _argc;
    argv = _argv;

    stor_dbgflags = DBG_ALL;
    qcoltype_t qtype_varchar;
    qtype_varchar.type = COLTYPE_VARCHAR;
    qtype_varchar.size = STOR_VARCHAR_MAX;
    QCOLTYPE_VARCHAR_DEFAULT = &qtype_varchar;

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
    RUN_TEST(test_blk_mark_hole_filled);
    RUN_TEST(test_blk_find_holes);
    RUN_TEST(test_db_blk_cpy_rec);
    RUN_TEST(test_update_single_value_diff_size_move_up);
    RUN_TEST(test_update_single_value_diff_size_move_same_block);
    RUN_TEST(test_update_single_value_diff_size_grow_down);
    RUN_TEST(test_update_single_value_diff_size_move_diff_block);
    RUN_TEST(test_varchar_value_bigger_than_255_chars);
    RUN_TEST(test_db_next_blkno);
    RUN_TEST(test_metainfo_can_be_larger_than_1_page);
    RUN_TEST(test_delete);
    SKIP_TEST(test_add_lots_of_small_recs);
    rm_test_db();
    END_TESTS();
    die("unreachable");
}
