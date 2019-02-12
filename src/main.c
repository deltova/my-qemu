#define _POSIX_C_SOURCE 200809L
#include <asm/processor-flags.h>
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
#include <unistd.h>
#include <getopt.h>
#include <string>

#include "debug.h"
#include "serial.h"
#include "constant.h"
static std::string cmdline;

void main_loop(int vcpufd, struct kvm_run *run, char *begin_addr_space) {
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  uint16_t port;
  (void)begin_addr_space;
  ioctl(vcpufd, KVM_GET_REGS, &regs);
  kvm_debug_dump(vcpufd, DEBUG_COMPLETE);
  while (1) {
    int ret = ioctl(vcpufd, KVM_RUN, NULL);
    ioctl(vcpufd, KVM_GET_REGS, &regs);
    ioctl(vcpufd, KVM_GET_SREGS, &sregs);
    if (ret == -1)
      err(1, "KVM_RUN");
    switch (run->exit_reason) {
      case KVM_EXIT_HLT:
        puts("KVM_EXIT_HLT");
        return;
      case KVM_EXIT_IO:
        port = run->io.port;
        if (port == RBR || port == IER || port == IIR || port == LCR
            || port == LSR || port == MCR || MSR == port)
          handle_serial_io(run);   
        else if (port == 0x61 || port == 0x43 || port == 0x42 || port == 0xcf8
                || port == 0xcfc || port == 0xcfe || port == 0xa1 || port == 0x21
                || port == 0x70 || port == 0x71 || port == 0x80 || port == 0x40)
          (void)port;
        else
        {
          //dump_io(run);
          //errx(1, "unhandled KVM_EXIT_IO");
        }
        break;
      case KVM_EXIT_MMIO:
        
        printf("MMIO: physaddr = 0x%llx\n", run->mmio.phys_addr);
        //disas(*handle, (void*)(regs.rip), (void*)(regs.rip + 10), 2); 
        break;
      case KVM_EXIT_FAIL_ENTRY:
        errx(1, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx",
            (unsigned long long)run->fail_entry.hardware_entry_failure_reason);
      case KVM_EXIT_INTERNAL_ERROR:
        printf("tpr_acces.rip: 0x%llx\n", run->tpr_access.rip);
        errx(1, "KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x",
            run->internal.suberror);
      case KVM_EXIT_DEBUG:
        break;
      default:
        puts("OTHER\n");
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

static void write_boot_param(struct setup_header *setup_header, void *end_setup_header, char *ram_addr)
{
  //get a clean boot_params
  struct boot_params *bt_param = (struct boot_params*)(ram_addr + BOOT_PARAM_ADDR);
  memset(bt_param, 0, sizeof(struct boot_params));

  //copy the setup_header in the boot params

  memcpy(&(bt_param->hdr), setup_header, (uintptr_t)end_setup_header - (uintptr_t)setup_header);

  if (bt_param->hdr.setup_sects == 0)
    bt_param->hdr.setup_sects = 4;

  bt_param->hdr.type_of_loader = 0xff;
  //Setup Load flags
  bt_param->hdr.loadflags = 0;
  bt_param->hdr.loadflags |= KEEP_SEGMENTS; //do not reload seg

	bt_param->hdr.loadflags &= ~QUIET_FLAG; // Print early messages
	bt_param->hdr.loadflags &= ~CAN_USE_HEAP; // heap_ptr is not valid*/

	init_e820_table(bt_param);

  //setup kernel Command Line
  bt_param->hdr.cmd_line_ptr = CMDLINE_ADDR;
  memcpy(ram_addr + CMDLINE_ADDR, cmdline.c_str(), cmdline.size());
}

static void *setup_memory(int vmfd, size_t ram_size)
{
  void *ram = mmap(NULL, ram_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (ram == MAP_FAILED)
  {
    errx(1, "mmap failed");
  }
  struct kvm_userspace_memory_region region; 
  memset(&region, 0, sizeof(struct kvm_userspace_memory_region));
  region.slot = 0;
  region.guest_phys_addr = 0x0;
  region.memory_size = RAM_SIZE;
  region.userspace_addr = (uint64_t)ram;
  int ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
  if (ret == -1)
    err(1, "KVM_SET_USER_MEMORY_REGION");
  return ram;
}

static void *load_bzImage(const char *image, int vmfd, size_t *kernel_size,
    size_t ram_size)
{
  int imagefd = open(image, O_RDWR);
  if (imagefd == -1)
    err(1, "open bzImage failed");

  struct stat statbuf;
  fstat(imagefd, &statbuf);
  size_t image_size = statbuf.st_size;

  uint8_t *mem = (uint8_t*)mmap(NULL, image_size, PROT_READ | PROT_WRITE, MAP_SHARED, imagefd,
      0);
  if (mem == MAP_FAILED)
  {
    errx(1, "load image failed");
  }
  
  struct setup_header *setup_header =
    (struct setup_header *)((char *)mem + OFF_SETUP_HEADER);

  uint64_t off_kernel = get_kernel_off(setup_header);

  
  char *ram_addr = (char*)setup_memory(vmfd, ram_size);
  void *end_setup_header = mem + 0x0202 +  *((char*)mem + 0x0201);
  write_boot_param(setup_header, end_setup_header, ram_addr);
  //write kernel
  *kernel_size = image_size - off_kernel; 

  memcpy(ram_addr + KERNEL_START, mem + off_kernel, *kernel_size);
  return ram_addr;
}

static void setup_protected_mode(struct kvm_sregs *sregs)
{
  struct kvm_segment seg;
  seg.base = 0;
  seg.limit = 0xffffffff;
  seg.selector = 0x8;
  seg.present = 1;
  seg.type = 11;
  seg.dpl = 0;
  seg.db = 1;
  seg.s = 1;
  seg.l = 0;
  seg.g = 1;

  sregs->cs = seg;

  seg.type = 3; /* Data: read/write, accessed */
  seg.selector = 0x10;
  sregs->ds = sregs->es = sregs->ss = seg;

  sregs->cr0 |= X86_CR0_PE;

  //disable paging
  sregs->cr4 &= ~(1U << 5);
}

static void setup_cpuid(int vcpufd)
{
  struct {
    struct kvm_cpuid a;
    struct kvm_cpuid_entry b[4];
  } cpuid_info;
  cpuid_info.a.nent = 4;
  cpuid_info.a.entries[0].function = 0;
  cpuid_info.a.entries[0].eax = 1;
  cpuid_info.a.entries[0].ebx = 0;
  cpuid_info.a.entries[0].ecx = 0;
  cpuid_info.a.entries[0].edx = 0;
  cpuid_info.a.entries[1].function = 1;
  cpuid_info.a.entries[1].eax = 0x400;
  cpuid_info.a.entries[1].ebx = 0;
  cpuid_info.a.entries[1].ecx = 0;
  cpuid_info.a.entries[1].edx = 0x701b179;
  cpuid_info.a.entries[2].function = 0x80000000;
  cpuid_info.a.entries[2].eax = 0x80000001;
  cpuid_info.a.entries[2].ebx = 0;
  cpuid_info.a.entries[2].ecx = 0;
  cpuid_info.a.entries[2].edx = 0;
  cpuid_info.a.entries[3].function = 0x80000001;
  cpuid_info.a.entries[3].eax = 0;
  cpuid_info.a.entries[3].ebx = 0;
  cpuid_info.a.entries[3].ecx = 0;
  cpuid_info.a.entries[3].edx = 0x20100800; 
  if (ioctl (vcpufd, KVM_SET_CPUID, &cpuid_info.a) < 0)
    err (1, "KVM_SET_CPUID failed");

}

static void activate_single_step(int vcpufd)
{
  int ret;
  struct kvm_guest_debug guest_debug;
  memset(&guest_debug, 0, sizeof(struct kvm_guest_debug));
  guest_debug.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;
  guest_debug.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;


  ret = ioctl(vcpufd, KVM_SET_GUEST_DEBUG, &guest_debug);
  if (ret == -1)
    err(1, "KVM_CAP_SET_GUEST_DEBUG");

}

static int create_vm(size_t *mmap_size)
{
  int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
  if (kvm == -1)
    err(1, "/dev/kvm");

  int ret = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
  if (ret == -1)
    err(1, "KVM_GET_VCPU_MMAP_SIZE");
  *mmap_size = ret;

  int vmfd = ioctl(kvm, KVM_CREATE_VM, (unsigned long)0);
  if (vmfd == -1)
    err(1, "KVM_CREATE_VM");
  return vmfd;
}

static void load_initramfs(char *initramfs, uint8_t *ram_begin, size_t kernel_size)
{
  int imagefd = open(initramfs, O_RDWR);
  if (imagefd == -1)
    err(1, "open bzImage failed");

  struct stat statbuf;
  fstat(imagefd, &statbuf);
  size_t image_size = statbuf.st_size;

  uint8_t *init = (uint8_t*)mmap(NULL, image_size, PROT_READ | PROT_WRITE, MAP_SHARED, imagefd,
      0);
  if (init == MAP_FAILED)
    errx(1, "load image failed");

  memcpy(ram_begin + kernel_size + KERNEL_START, init, statbuf.st_size);
  struct boot_params *bt_param = (struct boot_params*)(ram_begin + BOOT_PARAM_ADDR);
  struct setup_header *setup_header = &(bt_param->hdr);
  
  setup_header->ramdisk_image = (uint64_t)(kernel_size + KERNEL_START);
  setup_header->ramdisk_size = statbuf.st_size;
}

void parse_param(int argc, char **argv, char **bzimage_path,
    char **initrd_path, size_t *ram_disk)
{
  static struct option long_options[] =
  {
    {"h",       no_argument,       0, 'h'},
    {"initrd",  required_argument, 0, 'i'},
    {"m",       required_argument, 0, 'm'},
    {0, 0, 0, 0}
  };
  size_t ram_size = RAM_SIZE;
  char *initrd = NULL;
  int c;
  int option_index = 0;
  do
  {
    c = getopt_long (argc, argv, "hm:i:", long_options, &option_index);
    switch (c)
    {
      case 0:
        if (long_options[option_index].flag != 0)
          break;
        printf("option %s", long_options[option_index].name);
        if (optarg)
          printf(" with arg %s", optarg);
        printf("\n");
        break;
      case 'h':
        puts ("-m $ram_size\n --initrd initrd_path\n -h helper\n");
        exit(0);
        break;
      case 'i':
        initrd = optarg;
        break;
      case 'm':
        ram_size = atol(optarg);
        break;

      default:
        break;
    }
  }
  while (c != -1);
  cmdline = DEFAULT_CMDLINE;
  if (optind < argc)
  {
    if (optind == argc)
      errx(1, "need to add a bzImage\n");
    *bzimage_path = argv[optind++];
    for (;optind < argc; optind++)
    {
      cmdline += std::string(argv[optind]);
    }
  }
  *initrd_path = initrd;
  *ram_disk = ram_size;
}

int main(int argc, char **argv) {
  int vcpufd, ret;
  struct kvm_sregs sregs;
  size_t mmap_size;
  struct kvm_run *run;
  char *bzimage_path;
  char *initrd_path;
  size_t ram_size;
  parse_param(argc, argv, &bzimage_path, &initrd_path, &ram_size);

  int vmfd = create_vm(&mmap_size);

  struct kvm_pit_config pit_conf;
  pit_conf.flags = 0;
  ret = ioctl(vmfd, KVM_CREATE_PIT2, &pit_conf);
  if (ret == -1)
    err(1, "KVM_CREATE_PIT2");

  ret = ioctl(vmfd, KVM_CREATE_IRQCHIP, 0);
  if (ret == -1)
    err(1, "KVM_CREATE_IRQCHIP");


  vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)0);
  if (vcpufd == -1)
    err(1, "KVM_CREATE_VCPU");

  setup_cpuid(vcpufd);

  if (mmap_size < sizeof(*run))
    errx(1, "KVM_GET_VCPU_MMAP_SIZE unexpectedly small");

  run = (kvm_run*)mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
  if (!run)
    err(1, "mmap vcpu");

  size_t kernel_size;
  void *ram_addr = load_bzImage(bzimage_path, vmfd, &kernel_size, ram_size);
  if (initrd_path != NULL)
    load_initramfs(initrd_path, (uint8_t*)ram_addr, kernel_size);

  ret = ioctl(vcpufd, KVM_GET_SREGS, &sregs);
  if (ret == -1)
    err(1, "KVM_GET_SREGS");

  setup_protected_mode(&sregs);

  ret = ioctl(vcpufd, KVM_SET_SREGS, &sregs);
  if (ret == -1)
    err(1, "KVM_SET_SREGS");

  struct kvm_regs regs;
  memset(&regs, 0, sizeof(regs));
  regs.rip = KERNEL_START;
  regs.rsp = STACK_ADRR;
  regs.rsi = BOOT_PARAM_ADDR;
  regs.rbp = 0;
  regs.rdi = 0;
  regs.rbx = 0;
  ret = ioctl(vcpufd, KVM_SET_REGS, &regs);

  activate_single_step(vcpufd);

  main_loop(vcpufd, run, (char*)ram_addr);
}
