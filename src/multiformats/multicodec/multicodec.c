#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "multiformats/multicodec/multicodec.h"
#include "multiformats/multicodec/multicodec_table.h"

static const multicodec_map_t *multicodec_find_by_name(const char *name)
{
	size_t index;
	const multicodec_map_t *match;

	match = NULL;
	if ((name != NULL) && (name[0] != '\0'))
	{
		for (index = 0; index < multicodec_table_len; ++index)
		{
			const multicodec_map_t *entry;

			entry = &multicodec_table[index];
			if ((entry->name != NULL) &&
			    (strcmp(name, entry->name) == 0))
			{
				match = entry;
				break;
			}
		}
	}

	return match;
}

static const multicodec_map_t *multicodec_find_by_code(uint64_t code)
{
	size_t index;
	const multicodec_map_t *match;

	match = NULL;
	for (index = 0; index < multicodec_table_len; ++index)
	{
		const multicodec_map_t *entry;

		entry = &multicodec_table[index];
		if (entry->code == code)
		{
			match = entry;
			break;
		}
	}

	return match;
}

uint64_t multicodec_code_from_name(const char *name)
{
	const multicodec_map_t *entry;
	uint64_t code;

	entry = multicodec_find_by_name(name);
	code = UINT64_MAX;
	if (entry != NULL)
	{
		code = entry->code;
	}

	return code;
}

const char *multicodec_name_from_code(uint64_t code)
{
	const multicodec_map_t *entry;
	const char *name;

	entry = multicodec_find_by_code(code);
	name = NULL;
	if (entry != NULL)
	{
		name = entry->name;
	}

	return name;
}
