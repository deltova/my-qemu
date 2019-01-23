#pragma once

#define DEBUG_COMPLETE 1
#define DEBUG_REGS 2
#include <linux/kvm.h>
#include <capstone/capstone.h>
#include <sys/ioctl.h>

csh *get_dissambler_32();
csh *get_dissambler_64();

void disas(csh handle, void *beg, void *end, size_t max_inst);
void print_rip(int vcpufd);
void kvm_debug_dump(int vcpu_fd, int complete);
