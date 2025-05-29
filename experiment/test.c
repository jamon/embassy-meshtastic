
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    const uint8_t *bytes;
    int length;
} byte_array_t;

uint8_t xorHash(const uint8_t *p, size_t len)
{
    uint8_t code = 0;
    for (size_t i = 0; i < len; i++)
        code ^= p[i];
    return code;
}

uint32_t hash(const char *str)
{
    uint32_t hash = 5381;
    int c;

    while ((c = *str++) != 0)
        hash = ((hash << 5) + hash) + (unsigned char)c; /* hash * 33 + c */

    return hash;
}
int16_t gen_hash(const char *name, byte_array_t k)
{
    if (k.length < 0)
        return -1; // invalid
    else {
        uint8_t h = xorHash((const uint8_t *)name, strlen(name));

        h ^= xorHash(k.bytes, k.length);

        return h;
    }
}
int main() {
    uint32_t result = hash("LongFast");
    byte_array_t k = { (const uint8_t *)"AQ==", 4 };
    printf("Hash of 'LongFast': %u\n", result);
    printf("Hash as hex bytes: 0x%02x 0x%02x 0x%02x 0x%02x\n", 
        (result >> 24) & 0xFF, 
        (result >> 16) & 0xFF, 
        (result >> 8) & 0xFF, 
        result & 0xFF);

    int16_t gen_result = gen_hash("LongFast", k);
    if (gen_result < 0) {
        printf("Invalid key length.\n");
    } else {
        printf("Generated hash: %d 0x%02x\n", gen_result, gen_result);
    }
    return 0;
}
