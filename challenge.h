#ifndef CHALLENGE_H
#define CHALLENGE_H 1

#include <stdint.h>

/** challenge_t: This structure contains the pseudo-random challenge used for
 * authentication.
 */
typedef struct challenge_t {
	/** tv_sec as returned by gettimeofday */
	uint32_t sec;
	/** tv_usec as returned by gettimeofday + random value */
	uint32_t usec_rnd;
	/** random values */
	uint32_t random[6];
} __attribute__ ((packed)) challenge_t;


challenge_t* generate_challenge(void);
void generate_response(challenge_t *challenge);
int validate_challenge(challenge_t *local, challenge_t *remote);

#endif
