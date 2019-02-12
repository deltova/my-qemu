#include "debug.h"
#include <err.h>
#include <ctype.h>
#include <iostream>

#define get_dissambler(MODE) \
   csh *get_dissambler_##MODE() \
   { \
    static csh *handle = NULL; \
    if (!handle) \
    { \
      handle = (csh*)malloc(sizeof(csh)); \
      if (cs_open(CS_ARCH_X86, CS_MODE_##MODE, handle) != CS_ERR_OK) \
        printf("capstone opening failed\n"); \
      cs_option(*handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT); \
    } \
    return handle; \
   }

get_dissambler(64)
get_dissambler(32)

void disas(csh handle, void *beg, void *end, size_t max_inst)
{
   cs_insn* insn;
   size_t count = cs_disasm(handle, (const uint8_t*)beg, (uintptr_t)end - (uintptr_t)beg,
                          0x1000, 0, &insn);
   size_t j;
   for (j = 0; j < count && j < max_inst; j++)
   {
     printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
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

static void print_dtable(const char* name, struct kvm_dtable* dtable)
{
  fprintf(stderr, " %s                 %016lx  %08hx\n", name, (uint64_t)dtable->base,
          (uint16_t)dtable->limit);
}

static void print_segment(const char* name, struct kvm_segment* seg)
{
  fprintf(stderr, " %s       %04hx      %016lx  %08x  %02hhx    %x %x   %x  %x %x %x %x\n", name,
          (uint16_t)seg->selector, (uint64_t)seg->base, (uint32_t)seg->limit, (uint8_t)seg->type,
          seg->present, seg->dpl, seg->db, seg->s, seg->l, seg->g, seg->avl);
}

void kvm_debug_dump(int vcpu_fd, int complete)
{
  unsigned long cr0, cr2, cr3;
  unsigned long cr4, cr8;
  unsigned long rax, rbx, rcx;
  unsigned long rdx, rsi, rdi;
  unsigned long rbp, r8, r9;
  unsigned long r10, r11, r12;
  unsigned long r13, r14, r15;
  unsigned long rip, rsp;
  struct kvm_sregs sregs;
  unsigned long rflags;
  struct kvm_regs regs;

  if (ioctl(vcpu_fd, KVM_GET_REGS, &regs) < 0)
    err(1, "Could not get regs");

  rflags = regs.rflags;

  rip = regs.rip;
  rsp = regs.rsp;
  rax = regs.rax;
  rbx = regs.rbx;
  rcx = regs.rcx;
  rdx = regs.rdx;
  rsi = regs.rsi;
  rdi = regs.rdi;
  rbp = regs.rbp;
  r8 = regs.r8;
  r9 = regs.r9;
  r10 = regs.r10;
  r11 = regs.r11;
  r12 = regs.r12;
  r13 = regs.r13;
  r14 = regs.r14;
  r15 = regs.r15;

  fprintf(stdout, "--\n");
  fprintf(stdout, "\n Registers:\n");
  fprintf(stdout, " ----------\n");
  fprintf(stdout, " rip: %016lx   rsp: %016lx flags: %016lx\n", rip, rsp, rflags);
  fprintf(stdout, " rax: %016lx   rbx: %016lx   rcx: %016lx\n", rax, rbx, rcx);
  fprintf(stdout, " rdx: %016lx   rsi: %016lx   rdi: %016lx\n", rdx, rsi, rdi);
  fprintf(stdout, " rbp: %016lx    r8: %016lx    r9: %016lx\n", rbp, r8, r9);
  fprintf(stdout, " r10: %016lx   r11: %016lx   r12: %016lx\n", r10, r11, r12);
  fprintf(stdout, " r13: %016lx   r14: %016lx   r15: %016lx\n", r13, r14, r15);

  if (ioctl(vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
    err(1, "Could not get sregs");

  cr0 = sregs.cr0;
  cr2 = sregs.cr2;
  cr3 = sregs.cr3;
  cr4 = sregs.cr4;
  cr8 = sregs.cr8;

  fprintf(stdout, " cr0: %016lx   cr2: %016lx   cr3: %016lx\n", cr0, cr2, cr3);
  fprintf(stdout, " cr4: %016lx   cr8: %016lx\n", cr4, cr8);

  if (complete == DEBUG_COMPLETE)
  {
    fprintf(stdout, "\n Segment registers:\n");
    fprintf(stdout, " ------------------\n");
    fprintf(stdout, " register  selector  base              limit     type  p dpl db s l g avl\n");

    print_segment("cs ", &sregs.cs);
    print_segment("ss ", &sregs.ss);
    print_segment("ds ", &sregs.ds);
    print_segment("es ", &sregs.es);
    print_segment("fs ", &sregs.fs);
    print_segment("gs ", &sregs.gs);
    print_segment("tr ", &sregs.tr);
    print_segment("ldt", &sregs.ldt);

    print_dtable("gdt", &sregs.gdt);
    print_dtable("idt", &sregs.idt);
  }
  fprintf(stdout, "--\n");
}



