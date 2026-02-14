#ifndef MULTICODEC_TABLE_H
#define MULTICODEC_TABLE_H

#include <stddef.h>

#include "multicodec.h"
#include "multicodec_codes.h"

/**
 * @brief A mapping between a codec name and its numeric multicodec code.
 */
#define MULTICODEC_TABLE_COUNT ((size_t)591U)
extern const multicodec_map_t multicodec_table[MULTICODEC_TABLE_COUNT];

/**
 * @brief The number of mappings in the multicodec_table array.
 */
extern const size_t multicodec_table_len;

#endif /* MULTICODEC_TABLE_H */
