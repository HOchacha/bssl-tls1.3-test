/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_DECODER_H
# define ossl_OPENSSL_DECODER_H
# pragma once

# include "ossl/openssl/opensslconf.h"

# ifndef ossl_OPENSSL_NO_STDIO
#  include <stdio.h>
# endif
# include <stdarg.h>
# include <stddef.h>
# include "ossl/openssl/decodererr.h"
# include "ossl/openssl/types.h"
# include "ossl/openssl/core.h"

# ifdef __cplusplus
extern "C" {
# endif

ossl_OSSL_DECODER *ossl_OSSL_DECODER_fetch(ossl_OSSL_LIB_CTX *libctx, const char *name,
                                 const char *properties);
int ossl_OSSL_DECODER_up_ref(ossl_OSSL_DECODER *encoder);
void ossl_OSSL_DECODER_free(ossl_OSSL_DECODER *encoder);

const ossl_OSSL_PROVIDER *ossl_OSSL_DECODER_get0_provider(const ossl_OSSL_DECODER *encoder);
const char *ossl_OSSL_DECODER_get0_properties(const ossl_OSSL_DECODER *encoder);
const char *ossl_OSSL_DECODER_get0_name(const ossl_OSSL_DECODER *decoder);
const char *ossl_OSSL_DECODER_get0_description(const ossl_OSSL_DECODER *decoder);
int ossl_OSSL_DECODER_is_a(const ossl_OSSL_DECODER *encoder, const char *name);

void ossl_OSSL_DECODER_do_all_provided(ossl_OSSL_LIB_CTX *libctx,
                                  void (*fn)(ossl_OSSL_DECODER *encoder, void *arg),
                                  void *arg);
int ossl_OSSL_DECODER_names_do_all(const ossl_OSSL_DECODER *encoder,
                              void (*fn)(const char *name, void *data),
                              void *data);
const ossl_OSSL_PARAM *ossl_OSSL_DECODER_gettable_params(ossl_OSSL_DECODER *decoder);
int ossl_OSSL_DECODER_get_params(ossl_OSSL_DECODER *decoder, ossl_OSSL_PARAM params[]);

const ossl_OSSL_PARAM *ossl_OSSL_DECODER_settable_ctx_params(ossl_OSSL_DECODER *encoder);
ossl_OSSL_DECODER_CTX *ossl_OSSL_DECODER_CTX_new(void);
int ossl_OSSL_DECODER_CTX_set_params(ossl_OSSL_DECODER_CTX *ctx,
                                const ossl_OSSL_PARAM params[]);
void ossl_OSSL_DECODER_CTX_free(ossl_OSSL_DECODER_CTX *ctx);

/* Utilities that help set specific parameters */
int ossl_OSSL_DECODER_CTX_set_passphrase(ossl_OSSL_DECODER_CTX *ctx,
                                    const unsigned char *kstr, size_t klen);
int ossl_OSSL_DECODER_CTX_set_pem_password_cb(ossl_OSSL_DECODER_CTX *ctx,
                                         ossl_pem_password_cb *cb, void *cbarg);
int ossl_OSSL_DECODER_CTX_set_passphrase_cb(ossl_OSSL_DECODER_CTX *ctx,
                                       ossl_OSSL_PASSPHRASE_CALLBACK *cb,
                                       void *cbarg);
int ossl_OSSL_DECODER_CTX_set_passphrase_ui(ossl_OSSL_DECODER_CTX *ctx,
                                       const ossl_UI_METHOD *ui_method,
                                       void *ui_data);

/*
 * Utilities to read the object to decode, with the result sent to cb.
 * These will discover all provided methods
 */

int ossl_OSSL_DECODER_CTX_set_selection(ossl_OSSL_DECODER_CTX *ctx, int selection);
int ossl_OSSL_DECODER_CTX_set_input_type(ossl_OSSL_DECODER_CTX *ctx,
                                    const char *input_type);
int ossl_OSSL_DECODER_CTX_set_input_structure(ossl_OSSL_DECODER_CTX *ctx,
                                         const char *input_structure);
int ossl_OSSL_DECODER_CTX_add_decoder(ossl_OSSL_DECODER_CTX *ctx, ossl_OSSL_DECODER *decoder);
int ossl_OSSL_DECODER_CTX_add_extra(ossl_OSSL_DECODER_CTX *ctx,
                               ossl_OSSL_LIB_CTX *libctx, const char *propq);
int ossl_OSSL_DECODER_CTX_get_num_decoders(ossl_OSSL_DECODER_CTX *ctx);

typedef struct ossl_ossl_decoder_instance_st ossl_OSSL_DECODER_INSTANCE;
ossl_OSSL_DECODER *
ossl_OSSL_DECODER_INSTANCE_get_decoder(ossl_OSSL_DECODER_INSTANCE *decoder_inst);
void *
ossl_OSSL_DECODER_INSTANCE_get_decoder_ctx(ossl_OSSL_DECODER_INSTANCE *decoder_inst);
const char *
ossl_OSSL_DECODER_INSTANCE_get_input_type(ossl_OSSL_DECODER_INSTANCE *decoder_inst);
const char *
ossl_OSSL_DECODER_INSTANCE_get_input_structure(ossl_OSSL_DECODER_INSTANCE *decoder_inst,
                                          int *was_set);

typedef int ossl_OSSL_DECODER_CONSTRUCT(ossl_OSSL_DECODER_INSTANCE *decoder_inst,
                                   const ossl_OSSL_PARAM *params,
                                   void *construct_data);
typedef void ossl_OSSL_DECODER_CLEANUP(void *construct_data);

int ossl_OSSL_DECODER_CTX_set_construct(ossl_OSSL_DECODER_CTX *ctx,
                                   ossl_OSSL_DECODER_CONSTRUCT *construct);
int ossl_OSSL_DECODER_CTX_set_construct_data(ossl_OSSL_DECODER_CTX *ctx,
                                        void *construct_data);
int ossl_OSSL_DECODER_CTX_set_cleanup(ossl_OSSL_DECODER_CTX *ctx,
                                 ossl_OSSL_DECODER_CLEANUP *cleanup);
ossl_OSSL_DECODER_CONSTRUCT *ossl_OSSL_DECODER_CTX_get_construct(ossl_OSSL_DECODER_CTX *ctx);
void *ossl_OSSL_DECODER_CTX_get_construct_data(ossl_OSSL_DECODER_CTX *ctx);
ossl_OSSL_DECODER_CLEANUP *ossl_OSSL_DECODER_CTX_get_cleanup(ossl_OSSL_DECODER_CTX *ctx);

int ossl_OSSL_DECODER_export(ossl_OSSL_DECODER_INSTANCE *decoder_inst,
                        void *reference, size_t reference_sz,
                        ossl_OSSL_CALLBACK *export_cb, void *export_cbarg);

int ossl_OSSL_DECODER_from_bio(ossl_OSSL_DECODER_CTX *ctx, ossl_BIO *in);
#ifndef ossl_OPENSSL_NO_STDIO
int ossl_OSSL_DECODER_from_fp(ossl_OSSL_DECODER_CTX *ctx, FILE *in);
#endif
int ossl_OSSL_DECODER_from_data(ossl_OSSL_DECODER_CTX *ctx, const unsigned char **pdata,
                           size_t *pdata_len);

/*
 * Create the ossl_OSSL_DECODER_CTX with an associated type.  This will perform
 * an implicit ossl_OSSL_DECODER_fetch(), suitable for the object of that type.
 */
ossl_OSSL_DECODER_CTX *
ossl_OSSL_DECODER_CTX_new_for_pkey(ossl_EVP_PKEY **pkey,
                              const char *input_type,
                              const char *input_struct,
                              const char *keytype, int selection,
                              ossl_OSSL_LIB_CTX *libctx, const char *propquery);

# ifdef __cplusplus
}
# endif
#endif
