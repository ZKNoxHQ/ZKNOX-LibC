#ifndef BANDERSNATCH_PRECOMP_H
#define BANDERSNATCH_PRECOMP_H

#include <stdint.h>

// Returns pointers to the 2MSM precomputed table (4 points)
void bandersnatch_get_2msm_table(const uint8_t (**T_mx)[32], const uint8_t (**T_my)[32]);

// Returns pointers to the 4MSM precomputed table (16 points)
void bandersnatch_get_4msm_table(const uint8_t (**T_mx)[32], const uint8_t (**T_my)[32]);

#endif