#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

uint32_t murmur_hash32(const char* ptr, size_t size)
{
    const uint32_t k = 1540483477;
    uint32_t h = size;
    const uint32_t* p = (const uint32_t*)(ptr);
    while (size >= 4)
    {
        uint32_t x = *p;
        x *= k;
        x ^= x >> 24;
        x *= k;
        h *= k;
        h ^= x;
        ++p;
        size -= 4;
    }
    ptr = (const char*)(p);
    switch (size)
    {
        case 3:
            h ^= ptr[2] << 16;
        case 2:
            h ^= ptr[1] << 8;
        case 1:
            h ^= ptr[0];
            h *= 0x5bd1e995;
    }
    h ^= h >> 13;
    h *= 0x5bd1e995;
    h ^= h >> 15;

    return h;
}

void print_hex(const void *data, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        printf("%02x", ((const unsigned char*)data)[i]);
    }
}

int main(int argc, char* argv[])
{
    const char* prefix = "alinas-fsid-";

    char buf[4096] = {0};
    char* p = buf + sprintf(buf, "%s", prefix);
    size_t remained = sizeof(buf) - (p - buf);

    for (int i = 0; i < argc - 1; ++i)
    {
        char* end = p + snprintf(p, remained, "%s", argv[i + 1]);

        uint32_t hash = murmur_hash32(buf, end - buf);
        hash = htonl(hash);

        printf("%s-", argv[i + 1]);
        print_hex(&hash, 4);
        printf(" ");
    }

    return 0;
}
