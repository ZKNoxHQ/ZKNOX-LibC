#include <stdint.h>
#include <stddef.h>
#ifndef _ZKN_COMMON_H

#define _MASK_8 0xff
#define _MASK_16 0xffff
#define _MASK_32 0xffffffff

/* status flags*/
#define _ZKN_INITIALIZED 1

// 32-bit byte reverse
static inline uint32_t rev32(uint32_t value)
{
    return __builtin_bswap32(value);
}

// 64-bit byte reverse using two 32-bit operations
static inline uint64_t rev64(uint64_t value)
{
    uint32_t high = (uint32_t)(value >> 32);
    uint32_t low = (uint32_t)(value & 0xFFFFFFFF);

    // Swap bytes in each 32-bit part and swap their positions
    return ((uint64_t)rev32(low) << 32) | rev32(high);
}

// 128-bit byte reverse in-place using uint64_t array
static inline void rev128(uint64_t data[2])
{
    uint64_t temp = rev64(data[0]);
    data[0] = rev64(data[1]);
    data[1] = temp;
}

// 256-bit byte reverse in-place using uint64_t array
static inline void rev256(uint64_t data[4])
{
    uint64_t temp0 = rev64(data[0]);
    uint64_t temp1 = rev64(data[1]);
    data[0] = rev64(data[3]);
    data[1] = rev64(data[2]);
    data[2] = temp1;
    data[3] = temp0;
}

static inline void ByteSwap(uint8_t *data, size_t datalen)
{
    uint8_t tmp2;
    // the ByteSwap
    for (size_t i = 0; i < datalen / 2; i++)
    {
        tmp2 = data[i];
        data[i] = data[datalen / 2 - i];
        data[datalen / 2 - i] = tmp2;
    }
}

#endif
