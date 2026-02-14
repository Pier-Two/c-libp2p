#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "multiformats/multicodec/multicodec.h"
#include "multiformats/multicodec/multicodec_table.h"

static const multicodec_map_t *multicodec_find_by_name(const char *name)
{
    size_t index;

    if ((name == NULL) || (name[0] == '\0'))
    {
        return NULL;
    }

    for (index = 0; index < multicodec_table_len; ++index)
    {
        const multicodec_map_t *entry;

        entry = &multicodec_table[index];
        if (strcmp(name, entry->name) == 0)
        {
            return entry;
        }
    }

    return NULL;
}

static const multicodec_map_t *multicodec_find_by_code(uint64_t code)
{
    size_t index;

    for (index = 0; index < multicodec_table_len; ++index)
    {
        const multicodec_map_t *entry;

        entry = &multicodec_table[index];
        if (entry->code == code)
        {
            return entry;
        }
    }

    return NULL;
}

uint64_t multicodec_code_from_name(const char *name)
{
    const multicodec_map_t *entry;

    entry = multicodec_find_by_name(name);
    if (entry == NULL)
    {
        return UINT64_MAX;
    }

    return entry->code;
}

const char *multicodec_name_from_code(uint64_t code)
{
    const multicodec_map_t *entry;

    entry = multicodec_find_by_code(code);
    if (entry == NULL)
    {
        return NULL;
    }

    return entry->name;
}
