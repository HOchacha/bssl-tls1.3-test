/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_BIOERR_H
# define ossl_OPENSSL_BIOERR_H
# pragma once

# include "ossl/openssl/opensslconf.h"
# include "ossl/openssl/symhacks.h"
# include "ossl/openssl/cryptoerr_legacy.h"



/*
 * ossl_BIO reason codes.
 */
# define ossl_BIO_R_ACCEPT_ERROR                               100
# define ossl_BIO_R_ADDRINFO_ADDR_IS_NOT_AF_INET               141
# define ossl_BIO_R_AMBIGUOUS_HOST_OR_SERVICE                  129
# define ossl_BIO_R_BAD_FOPEN_MODE                             101
# define ossl_BIO_R_BROKEN_PIPE                                124
# define ossl_BIO_R_CONNECT_ERROR                              103
# define ossl_BIO_R_CONNECT_TIMEOUT                            147
# define ossl_BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET          107
# define ossl_BIO_R_GETSOCKNAME_ERROR                          132
# define ossl_BIO_R_GETSOCKNAME_TRUNCATED_ADDRESS              133
# define ossl_BIO_R_GETTING_SOCKTYPE                           134
# define ossl_BIO_R_INVALID_ARGUMENT                           125
# define ossl_BIO_R_INVALID_SOCKET                             135
# define ossl_BIO_R_IN_USE                                     123
# define ossl_BIO_R_LENGTH_TOO_LONG                            102
# define ossl_BIO_R_LISTEN_V6_ONLY                             136
# define ossl_BIO_R_LOOKUP_RETURNED_NOTHING                    142
# define ossl_BIO_R_MALFORMED_HOST_OR_SERVICE                  130
# define ossl_BIO_R_NBIO_CONNECT_ERROR                         110
# define ossl_BIO_R_NO_ACCEPT_ADDR_OR_SERVICE_SPECIFIED        143
# define ossl_BIO_R_NO_HOSTNAME_OR_SERVICE_SPECIFIED           144
# define ossl_BIO_R_NO_PORT_DEFINED                            113
# define ossl_BIO_R_NO_SUCH_FILE                               128
# define ossl_BIO_R_NULL_PARAMETER                             115 /* unused */
# define ossl_BIO_R_TRANSFER_ERROR                             104
# define ossl_BIO_R_TRANSFER_TIMEOUT                           105
# define ossl_BIO_R_UNABLE_TO_BIND_SOCKET                      117
# define ossl_BIO_R_UNABLE_TO_CREATE_SOCKET                    118
# define ossl_BIO_R_UNABLE_TO_KEEPALIVE                        137
# define ossl_BIO_R_UNABLE_TO_LISTEN_SOCKET                    119
# define ossl_BIO_R_UNABLE_TO_NODELAY                          138
# define ossl_BIO_R_UNABLE_TO_REUSEADDR                        139
# define ossl_BIO_R_UNAVAILABLE_IP_FAMILY                      145
# define ossl_BIO_R_UNINITIALIZED                              120
# define ossl_BIO_R_UNKNOWN_INFO_TYPE                          140
# define ossl_BIO_R_UNSUPPORTED_IP_FAMILY                      146
# define ossl_BIO_R_UNSUPPORTED_METHOD                         121
# define ossl_BIO_R_UNSUPPORTED_PROTOCOL_FAMILY                131
# define ossl_BIO_R_WRITE_TO_READ_ONLY_BIO                     126
# define ossl_BIO_R_WSASTARTUP                                 122

#endif
