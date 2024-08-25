/*
 * Copyright 2007-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_CMP_UTIL_H
# define ossl_OPENSSL_CMP_UTIL_H
# pragma once

# include "ossl/openssl/opensslconf.h"
# ifndef ossl_OPENSSL_NO_CMP

#  include "ossl/openssl/macros.h"
#  include "ossl/openssl/trace.h"

#  ifdef __cplusplus
extern "C" {
#  endif

int  ossl_OSSL_CMP_log_open(void);
void ossl_OSSL_CMP_log_close(void);
#  define ossl_OSSL_CMP_LOG_PREFIX "CMP "

/*
 * generalized logging/error callback mirroring the severity levels of syslog.h
 */
typedef int ossl_OSSL_CMP_severity;
#  define ossl_OSSL_CMP_LOG_EMERG   0
#  define ossl_OSSL_CMP_LOG_ALERT   1
#  define ossl_OSSL_CMP_LOG_CRIT    2
#  define ossl_OSSL_CMP_LOG_ERR     3
#  define ossl_OSSL_CMP_LOG_WARNING 4
#  define ossl_OSSL_CMP_LOG_NOTICE  5
#  define ossl_OSSL_CMP_LOG_INFO    6
#  define ossl_OSSL_CMP_LOG_DEBUG   7
#  define ossl_OSSL_CMP_LOG_TRACE   8
#  define ossl_OSSL_CMP_LOG_MAX     ossl_OSSL_CMP_LOG_TRACE
typedef int (*ossl_OSSL_CMP_log_cb_t)(const char *func, const char *file, int line,
                                 ossl_OSSL_CMP_severity level, const char *msg);

int ossl_OSSL_CMP_print_to_bio(ossl_BIO *bio, const char *component, const char *file,
                          int line, ossl_OSSL_CMP_severity level, const char *msg);
/* use of the logging callback for outputting error queue */
void ossl_OSSL_CMP_print_errors_cb(ossl_OSSL_CMP_log_cb_t log_fn);

#  ifdef  __cplusplus
}
#  endif
# endif /* !defined(ossl_OPENSSL_NO_CMP) */
#endif /* !defined(ossl_OPENSSL_CMP_UTIL_H) */
