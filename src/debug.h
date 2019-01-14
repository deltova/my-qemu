#pragma once

#include <capstone/capstone.h>

csh *get_dissambler_32();
csh *get_dissambler_64();

void disas(csh handle, void *beg, void *end);
