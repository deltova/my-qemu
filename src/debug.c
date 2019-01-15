#include "debug.h"
#include <ctype.h>

#define get_dissambler(MODE) \
   csh *get_dissambler_##MODE() \
   { \
    static csh *handle = NULL; \
    if (!handle) \
    { \
      handle = malloc(sizeof(csh)); \
      if (cs_open(CS_ARCH_X86, CS_MODE_##MODE, handle) != CS_ERR_OK) \
        printf("capstone opening failed\n"); \
    } \
    return handle; \
   }

get_dissambler(64)
get_dissambler(32)

void disas(csh handle, void *beg, void *end)
{
   cs_insn* insn;
   size_t count = cs_disasm(handle, beg, (uintptr_t)end - (uintptr_t)beg,
                          0x1000, 0, &insn);
   size_t j;
   for (j = 0; j < count; j++)
   {
     printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
     insn[j].op_str);
   }
   cs_free(insn, count);
}

void print_rip(int vcpufd)
{
  struct kvm_regs regs;
  ioctl(vcpufd, KVM_GET_REGS, &regs);
  printf("rip: 0x%llx\n", regs.rip);
}
