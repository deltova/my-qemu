#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <asm/bootparam.h>
#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <asm/e820.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "debug.h"

#define DEFAULT_CMDLINE "console=ttyS0 earlyprintk=serial nokaslr"
#define BOOT_PARAM_ADDR 0x6000
#define CMDLINE_ADDR	BOOT_PARAM_ADDR + 0x10000
#define SERIAL_ADDR 0x3f8
#define OFF_SETUP_HEADER 0x01f1
#define RAM_SIZE 1 << 30
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

static inline void set_e820_entry(struct boot_e820_entry *entry, uint64_t addr,
				  uint64_t size, uint32_t type)
{
	entry->addr = addr;
	entry->size = size;
	entry->type = type;
}

static void init_e820_table(struct boot_params *params)
{
	uint8_t idx = 0;
	struct boot_e820_entry *pre_isa = &params->e820_table[idx++];
	struct boot_e820_entry *post_isa = &params->e820_table[idx++];

	set_e820_entry(pre_isa, 0x0, ISA_START_ADDRESS - 1, E820_RAM);
	set_e820_entry(post_isa, ISA_END_ADDRESS, (200 << 20) - ISA_END_ADDRESS,
		       E820_RAM);

	params->e820_entries = idx;
}

static uint64_t get_kernel_off(struct setup_header *setup_header)
{
  uint8_t setup_sects = setup_header->setup_sects; 
  if (setup_sects == 0)
    setup_sects = 4;
  return (setup_sects + 1) * 512;
}

static void write_boot_param(struct setup_header *setup_header, char *ram_addr)
{
  //get a clean boot_params
  struct boot_params *bt_param = (struct boot_params*)(ram_addr + BOOT_PARAM_ADDR);
  memset(bt_param, 0, sizeof(struct boot_params));

  //copy the setup_header in the boot params
  memcpy(setup_header, &(bt_param->hdr), sizeof(struct setup_header));

  if (bt_param->hdr.setup_sects == 0)
    bt_param->hdr.setup_sects = 4;

  //Setup Load flags
  bt_param->hdr.loadflags |= KEEP_SEGMENTS; //do not reload seg
	bt_param->hdr.loadflags &= ~QUIET_FLAG; // Print early messages
	bt_param->hdr.loadflags &= ~CAN_USE_HEAP; // heap_ptr is not valid

	init_e820_table(bt_param);

  //setup kernel Command Line
  bt_param->hdr.cmd_line_ptr = CMDLINE_ADDR;
  memcpy(ram_addr + CMDLINE_ADDR, DEFAULT_CMDLINE, strlen(DEFAULT_CMDLINE) + 1);
}

static void *setup_memory(int vmfd)
{
  void *ram = mmap(NULL, RAM_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  struct kvm_userspace_memory_region region = {
    .slot = 0,
    .guest_phys_addr = 0x0,
    .memory_size = RAM_SIZE,
    .userspace_addr = (uint64_t)ram,
  };
  int ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
  if (ret == -1)
    err(1, "KVM_SET_USER_MEMORY_REGION");
  return ram;
}

static void load_bzImage(const char *image, int vmfd)
{
  int imagefd = open(image, O_RDWR);
  if (imagefd == -1)
    err(1, "open bzImage failed");

  struct stat statbuf;
  fstat(imagefd, &statbuf);
  size_t image_size = statbuf.st_size;

  uint8_t *mem = mmap(NULL, image_size, PROT_READ | PROT_WRITE, MAP_SHARED, imagefd,
      0);
  
  struct setup_header *setup_header =
    (struct setup_header *)((char *)mem + OFF_SETUP_HEADER);

  uint64_t off_kernel = get_kernel_off(setup_header);

  
  void *ram_addr = setup_memory(vmfd);
  write_boot_param(setup_header, ram_addr);
  //write kernel
  size_t kernel_size = image_size - off_kernel; 

  memcpy(ram_addr + 0x100000, ram_addr + off_kernel, kernel_size);
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
