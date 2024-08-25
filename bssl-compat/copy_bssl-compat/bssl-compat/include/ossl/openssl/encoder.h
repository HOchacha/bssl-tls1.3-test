/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_ENCODER_H
# define ossl_OPENSSL_ENCODER_H
# pragma once

# include "ossl/openssl/opensslconf.h"

# ifndef ossl_OPENSSL_NO_STDIO
#  include <stdio.h>
# endif
# include <stdarg.h>
# include <stddef.h>
# include "ossl/openssl/encodererr.h"
# include "ossl/openssl/types.h"
# include "ossl/openssl/core.h"

# ifdef __cplusplus
extern "C" {
# endif

ossl_OSSL_ENCODER *ossl_OSSL_ENCODER_fetch(ossl_OSSL_LIB_CTX *libctx, const char *name,
                                 const char *properties);
int ossl_OSSL_ENCODER_up_ref(ossl_OSSL_ENCODER *encoder);
void ossl_OSSL_ENCODER_free(ossl_OSSL_ENCODER *encoder);

const ossl_OSSL_PROVIDER *ossl_OSSL_ENCODER_get0_provider(const ossl_OSSL_ENCODER *encoder);
const char *ossl_OSSL_ENCODER_get0_properties(const ossl_OSSL_ENCODER *encoder);
const char *ossl_OSSL_ENCODER_get0_name(const ossl_OSSL_ENCODER *kdf);
const char *ossl_OSSL_ENCODER_get0_description(const ossl_OSSL_ENCODER *kdf);
int ossl_OSSL_ENCODER_is_a(const ossl_OSSL_ENCODER *encoder, const char *name);

void ossl_OSSL_ENCODER_do_all_provided(ossl_OSSL_LIB_CTX *libctx,
                                  void (*fn)(ossl_OSSL_ENCODER *encoder, void *arg),
                                  void *arg);
int ossl_OSSL_ENCODER_names_do_all(const ossl_OSSL_ENCODER *encoder,
                              void (*fn)(const char *name, void *data),
                              void *data);
const ossl_OSSL_PARAM *ossl_OSSL_ENCODER_gettable_params(ossl_OSSL_ENCODER *encoder);
int ossl_OSSL_ENCODER_get_params(ossl_OSSL_ENCODER *encoder, ossl_OSSL_PARAM params[]);

const ossl_OSSL_PARAM *ossl_OSSL_ENCODER_settable_ctx_params(ossl_OSSL_ENCODER *encoder);
ossl_OSSL_ENCODER_CTX *ossl_OSSL_ENCODER_CTX_new(void);
int ossl_OSSL_ENCODER_CTX_set_params(ossl_OSSL_ENCODER_CTX *ctx,
                                const ossl_OSSL_PARAM params[]);
void ossl_OSSL_ENCODER_CTX_free(ossl_OSSL_ENCODER_CTX *ctx);

/* Utilities that help set specific parameters */
int ossl_OSSL_ENCODER_CTX_set_passphrase(ossl_OSSL_ENCODER_CTX *ctx,
                                    const unsigned char *kstr, size_t klen);
int ossl_OSSL_ENCODER_CTX_set_pem_password_cb(ossl_OSSL_ENCODER_CTX *ctx,
                                         ossl_pem_password_cb *cb, void *cbarg);
int ossl_OSSL_ENCODER_CTX_set_passphrase_cb(ossl_OSSL_ENCODER_CTX *ctx,
                                       ossl_OSSL_PASSPHRASE_CALLBACK *cb,
                                       void *cbarg);
int ossl_OSSL_ENCODER_CTX_set_passphrase_ui(ossl_OSSL_ENCODER_CTX *ctx,
                                       const ossl_UI_METHOD *ui_method,
                                       void *ui_data);
int ossl_OSSL_ENCODER_CTX_set_cipher(ossl_OSSL_ENCODER_CTX *ctx,
                                const char *cipher_name,
                                const char *propquery);
int ossl_OSSL_ENCODER_CTX_set_selection(ossl_OSSL_ENCODER_CTX *ctx, int selection);
int ossl_OSSL_ENCODER_CTX_set_output_type(ossl_OSSL_ENCODER_CTX *ctx,
                                     const char *output_type);
int ossl_OSSL_ENCODER_CTX_set_output_structure(ossl_OSSL_ENCODER_CTX *ctx,
                                          const char *output_structure);

/* Utilities to add encoders */
int ossl_OSSL_ENCODER_CTX_add_encoder(ossl_OSSL_ENCODER_CTX *ctx, ossl_OSSL_ENCODER *encoder);
int ossl_OSSL_ENCODER_CTX_add_extra(ossl_OSSL_ENCODER_CTX *ctx,
                               ossl_OSSL_LIB_CTX *libctx, const char *propq);
int ossl_OSSL_ENCODER_CTX_get_num_encoders(ossl_OSSL_ENCODER_CTX *ctx);

typedef struct ossl_ossl_encoder_instance_st ossl_OSSL_ENCODER_INSTANCE;
ossl_OSSL_ENCODER *
ossl_OSSL_ENCODER_INSTANCE_get_encoder(ossl_OSSL_ENCODER_INSTANCE *encoder_inst);
void *
ossl_OSSL_ENCODER_INSTANCE_get_encoder_ctx(ossl_OSSL_ENCODER_INSTANCE *encoder_inst);
const char *
ossl_OSSL_ENCODER_INSTANCE_get_output_type(ossl_OSSL_ENCODER_INSTANCE *encoder_inst);
const char *
ossl_OSSL_ENCODER_INSTANCE_get_output_structure(ossl_OSSL_ENCODER_INSTANCE *encoder_inst);

typedef const void *ossl_OSSL_ENCODER_CONSTRUCT(ossl_OSSL_ENCODER_INSTANCE *encoder_inst,
                                           void *construct_data);
typedef void ossl_OSSL_ENCODER_CLEANUP(void *construct_data);

int ossl_OSSL_ENCODER_CTX_set_construct(ossl_OSSL_ENCODER_CTX *ctx,
                                   ossl_OSSL_ENCODER_CONSTRUCT *construct);
int ossl_OSSL_ENCODER_CTX_set_construct_data(ossl_OSSL_ENCODER_CTX *ctx,
                                        void *construct_data);
int ossl_OSSL_ENCODER_CTX_set_cleanup(ossl_OSSL_ENCODER_CTX *ctx,
                                 ossl_OSSL_ENCODER_CLEANUP *cleanup);

/* Utilities to output the object to encode */
int ossl_OSSL_ENCODER_to_bio(ossl_OSSL_ENCODER_CTX *ctx, ossl_BIO *out);
#ifndef ossl_OPENSSL_NO_STDIO
int ossl_OSSL_ENCODER_to_fp(ossl_OSSL_ENCODER_CTX *ctx, FILE *fp);
#endif
int ossl_OSSL_ENCODER_to_data(ossl_OSSL_ENCODER_CTX *ctx, unsigned char **pdata,
                         size_t *pdata_len);

/*
 * Create the ossl_OSSL_ENCODER_CTX with an associated type.  This will perform
 * an implicit ossl_OSSL_ENCODER_fetch(), suitable for the object of that type.
 * This is more useful than calling ossl_OSSL_ENCODER_CTX_new().
 */
ossl_OSSL_ENCODER_CTX *ossl_OSSL_ENCODER_CTX_new_for_pkey(const ossl_EVP_PKEY *pkey,
                                                int selection,
                                                const char *output_type,
                                                const char *output_struct,
                                                const char *propquery);

# ifdef __cplusplus
}
# endif
#endif
