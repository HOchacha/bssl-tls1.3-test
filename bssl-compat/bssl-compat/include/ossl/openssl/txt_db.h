/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_TXT_DB_H
# define ossl_OPENSSL_TXT_DB_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_TXT_DB_H
# endif

# include "ossl/openssl/opensslconf.h"
# include "ossl/openssl/bio.h"
# include "ossl/openssl/safestack.h"
# include "ossl/openssl/lhash.h"

# define ossl_DB_ERROR_OK                     0
# define ossl_DB_ERROR_MALLOC                 1
# define ossl_DB_ERROR_INDEX_CLASH            2
# define ossl_DB_ERROR_INDEX_OUT_OF_RANGE     3
# define ossl_DB_ERROR_NO_INDEX               4
# define ossl_DB_ERROR_INSERT_INDEX_CLASH     5
# define ossl_DB_ERROR_WRONG_NUM_FIELDS       6

#ifdef  __cplusplus
extern "C" {
#endif

typedef ossl_OPENSSL_STRING *ossl_OPENSSL_PSTRING;
ossl_DEFINE_SPECIAL_STACK_OF(ossl_OPENSSL_PSTRING, ossl_OPENSSL_STRING)

typedef struct ossl_txt_db_st {
    int num_fields;
    ossl_STACK_OF(ossl_OPENSSL_PSTRING) *data;
    ossl_LHASH_OF(ossl_OPENSSL_STRING) **index;
    int (**qual) (ossl_OPENSSL_STRING *);
    long error;
    long arg1;
    long arg2;
    ossl_OPENSSL_STRING *arg_row;
} ossl_TXT_DB;

ossl_TXT_DB *ossl_TXT_DB_read(ossl_BIO *in, int num);
long ossl_TXT_DB_write(ossl_BIO *out, ossl_TXT_DB *db);
int ossl_TXT_DB_create_index(ossl_TXT_DB *db, int field, int (*qual) (ossl_OPENSSL_STRING *),
                        ossl_OPENSSL_LH_HASHFUNC hash, ossl_OPENSSL_LH_COMPFUNC cmp);
void ossl_TXT_DB_free(ossl_TXT_DB *db);
ossl_OPENSSL_STRING *ossl_TXT_DB_get_by_index(ossl_TXT_DB *db, int idx,
                                    ossl_OPENSSL_STRING *value);
int ossl_TXT_DB_insert(ossl_TXT_DB *db, ossl_OPENSSL_STRING *value);

#ifdef  __cplusplus
}
#endif

#endif
