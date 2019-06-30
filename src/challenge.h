/*
 * challenge.h
 * ptunnel is licensed under the BSD license:
 *
 * Copyright (c) 2004-2011, Daniel Stoedle <daniels@cs.uit.no>,
 * Yellow Lemon Software. All rights reserved.
 *
 * Copyright (c) 2017-2019, Toni Uhlig <matzeton@googlemail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * - Neither the name of the Yellow Lemon Software nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Contacting the author:
 * You can get in touch with me, Daniel Stødle (that's the Norwegian letter oe,
 * in case your text editor didn't realize), here: <daniels@cs.uit.no>
 *
 * The official ptunnel website is here:
 * <http://www.cs.uit.no/~daniels/PingTunnel/>
 *
 * Note that the source code is best viewed with tabs set to 4 spaces.
 */

#ifndef CHALLENGE_H
#define CHALLENGE_H 1

#include "pconfig.h"

#include <stdint.h>
#ifdef ENABLE_SHA512
#include <openssl/sha.h>
#endif

#define HT_MD5    0x1
#define HT_SHA512 0x2


typedef struct challenge_plain_t {
	/** tv_sec as returned by gettimeofday */
	uint32_t sec;
	/** tv_usec as returned by gettimeofday + random value */
	uint32_t usec_rnd;
	/** random values */
	uint32_t random[6];
} __attribute__ ((packed)) challenge_plain_t;

typedef struct challenge_digest_t {
	uint8_t hash_type;
	union {
		unsigned char md5[kMD5_digest_size];
		unsigned char sha512[kSHA512_digest_size];
	};
} __attribute__ ((packed)) challenge_digest_t;

/** challenge_t: This structure contains the pseudo-random challenge used for
 * authentication. If OpenSSL is available SHA512 will be used per default.
 */
typedef struct challenge_t {
	challenge_plain_t plain;
	challenge_digest_t digest;
} __attribute__ ((packed)) challenge_t;

challenge_t *generate_challenge(void);

void generate_response_md5(challenge_plain_t *plain, challenge_digest_t *digest);
int validate_challenge_md5(challenge_t *local, challenge_digest_t *remote);

#ifdef ENABLE_SHA512
void generate_response_sha512(challenge_plain_t *plain, challenge_digest_t *digest);
int validate_challenge_sha512(challenge_t *local, challenge_digest_t *remote);
#endif

#endif
