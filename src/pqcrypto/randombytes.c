/* LanaCoin: randomness for PQClean code, taken from OpenSSL's CSPRNG */
#include "randombytes.h"

#include <openssl/rand.h>
#include <limits.h>

int randombytes(uint8_t *output, size_t n) {
    while (n > 0) {
        int chunk = n > INT_MAX ? INT_MAX : (int)n;
        if (RAND_bytes(output, chunk) != 1) {
            return -1;
        }
        output += chunk;
        n -= (size_t)chunk;
    }
    return 0;
}
