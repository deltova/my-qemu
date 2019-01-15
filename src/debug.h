#pragma once

#include <linux/kvm.h>
#include <capstone/capstone.h>
#include <sys/ioctl.h>

csh *get_dissambler_32();
csh *get_dissambler_64();

void disas(csh handle, void *beg, void *end);
void print_rip(int vcpufd);
