#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <asm/bootparam.h>
#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "debug.h"

#define SERIAL_ADDR 0x3f8
#define OFF_SETUP_HEADER 0x01f1
#define CR0_PE 1u

void main_loop(int vcpufd, struct kvm_run *run) {
  while (1) {
    int ret = ioctl(vcpufd, KVM_RUN, NULL);
    print_rip(vcpufd);
    printf("ret: %d\n", ret);
    if (ret == -1)
      err(1, "KVM_RUN");
    switch (run->exit_reason) {
      case KVM_EXIT_HLT:
        puts("KVM_EXIT_HLT");
        return;
      case KVM_EXIT_IO:
        if (run->io.direction == KVM_EXIT_IO_OUT && run->io.size == 1 &&
            run->io.port == SERIAL_ADDR && run->io.count == 1)
          putchar(*(((char *)run) + run->io.data_offset));
        else
          errx(1, "unhandled KVM_EXIT_IO");
        break;
      case KVM_EXIT_FAIL_ENTRY:
        errx(1, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx",
            (unsigned long long)run->fail_entry.hardware_entry_failure_reason);
      case KVM_EXIT_INTERNAL_ERROR:
        printf("tpr_acces.rip: 0x%llx\n", run->tpr_access.rip);
        errx(1, "KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x",
            run->internal.suberror);
      default:
        errx(1, "exit_reason = 0x%x", run->exit_reason);
    }
  }
}

void load_bzImage(const char *image, int vmfd)
{
  int imagefd = open(image, O_RDWR);
  if (imagefd == -1)
    err(1, "open bzImage failed");

  struct stat statbuf;
  fstat(imagefd, &statbuf);

  uint8_t *mem = mmap(NULL, statbuf.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, imagefd,
      0);
  struct boot_params *setup_header =
    (struct boot_params *)((char *)mem + OFF_SETUP_HEADER);
  (void)setup_header;

  struct kvm_userspace_memory_region region = {
    .slot = 0,
    .guest_phys_addr = 0x1000,
    .memory_size = 0x1000,
    .userspace_addr = (uint64_t)mem,
  };
  int ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
  if (ret == -1)
    err(1, "KVM_SET_USER_MEMORY_REGION");
}

static void setup_protected_mode(struct kvm_sregs *sregs)
{
  struct kvm_segment seg = {
    .base = 0,
    .limit = 0xffffffff,
    .selector = 1 << 3,
    .present = 1,
    .type = 11, /* Code: execute, read, accessed */
    .dpl = 0,
    .db = 1,
    .s = 1, /* Code/data */
    .l = 0,
    .g = 1, /* 4KB granularity */
  };

  sregs->cr0 |= CR0_PE; /* enter protected mode */

  sregs->cs = seg;

  seg.type = 3; /* Data: read/write, accessed */
  seg.selector = 2 << 3;
  sregs->ds = sregs->es = sregs->ss = seg;
}



int main(void) {
  int kvm, vmfd, vcpufd, ret;
  struct kvm_sregs sregs;
  size_t mmap_size;
  struct kvm_run *run;
  // struct boot_params parameter;

  kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
  if (kvm == -1)
    err(1, "/dev/kvm");

  vmfd = ioctl(kvm, KVM_CREATE_VM, (unsigned long)0);
  if (vmfd == -1)
    err(1, "KVM_CREATE_VM");

  load_bzImage("test-image/bzImage", vmfd);

  vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)0);
  if (vcpufd == -1)
    err(1, "KVM_CREATE_VCPU");

  ret = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
  if (ret == -1)
    err(1, "KVM_GET_VCPU_MMAP_SIZE");
  mmap_size = ret;
  if (mmap_size < sizeof(*run))
    errx(1, "KVM_GET_VCPU_MMAP_SIZE unexpectedly small");
  run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
  if (!run)
    err(1, "mmap vcpu");

  ret = ioctl(vcpufd, KVM_GET_SREGS, &sregs);
  if (ret == -1)
    err(1, "KVM_GET_SREGS");

  setup_protected_mode(&sregs);

  ret = ioctl(vcpufd, KVM_SET_SREGS, &sregs);
  if (ret == -1)
    err(1, "KVM_SET_SREGS");

  struct kvm_regs regs = {
    .rip = 0x1000,
  };
  ret = ioctl(vcpufd, KVM_SET_REGS, &regs);
  if (ret == -1)
    err(1, "KVM_SET_REGS");
  main_loop(vcpufd, run);
}
