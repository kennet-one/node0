#pragma once

#include <stdbool.h>
#include <stddef.h>

void	time_sync_start(void);
bool	time_sync_is_valid(void);
void	time_sync_format(char *out, size_t out_len);	// "YYYY-MM-DD HH:MM:SS"
