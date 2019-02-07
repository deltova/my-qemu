#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <err.h>

#include "serial.h"

static uint8_t line_config = 0;
static uint8_t interrupt_enable = 0;
static uint8_t interrupt_identification = 0;
static uint8_t modem_control = 0;
static uint8_t modem_status = 0;
static uint8_t line_status = 1 << 5 | 1 << 6;

void dump_io(struct kvm_run *run)
{
  char *direction;
  if (run->io.direction == KVM_EXIT_IO_IN)
    direction = "IN";
  else
    direction = "OUT";
  printf("io: dir: %s port: 0x%x size: %u off: %llu\n",
      direction, run->io.port, run->io.size, run->io.data_offset);
}

void handle_out(struct kvm_run *run)
{
  if (run->io.port == RBR)
  {
      putchar(*(((char *)run) + run->io.data_offset));
  }
  //Interrupt Enable Register
  else if (run->io.port == IER)
  {
    uint8_t enable_bit = *((uint8_t*)run + run->io.data_offset);
    interrupt_enable = enable_bit;
  }
  else if (run->io.port == IIR)
  {
    uint8_t enable_bit = *((uint8_t*)run + run->io.data_offset);
    interrupt_identification = enable_bit;
  }
  //Line Configure Register
  else if (run->io.port == LCR)
  {
    uint8_t enable_bit = *((uint8_t*)run + run->io.data_offset);
    line_config =  enable_bit;
  }
  else if (run->io.port == MCR)
  {
    uint8_t enable_bit = *((uint8_t*)run + run->io.data_offset);
    modem_control = enable_bit;
  }
  else if (run->io.port == LSR)
  {
    uint8_t enable_bit = *((uint8_t*)run + run->io.data_offset);
    line_status =  enable_bit;
  }
  else if (run->io.port == MSR)
  {
    uint8_t enable_bit = *((uint8_t*)run + run->io.data_offset);
    modem_status = enable_bit;
  }
  else
  {
    dump_io(run);
    errx(1, "not implemented\n");
  }
}

void handle_in(struct kvm_run *run)
{
  if (run->io.port == RBR)
  {
    //uint8_t *reg = (uint8_t*)run + run->io.data_offset;
    //reg = getchar();
    printf("TRY to trasmit\n");
  }
  else if (run->io.port == IER)
  {
    uint8_t *reg = (uint8_t*)run + run->io.data_offset;
    *reg = interrupt_enable;
  }
  else if (run->io.port == IIR)
  {
    uint8_t *reg = (uint8_t*)run + run->io.data_offset;
    *reg = interrupt_identification;
  }
  else if (run->io.port == LCR) 
  {
    uint8_t *reg = (uint8_t*)run + run->io.data_offset;
    *reg = line_config;
  }
  else if (run->io.port == MCR)
  {
    uint8_t *reg = (uint8_t*)run + run->io.data_offset;
    *reg = modem_control;
  }
  else if (run->io.port == LSR)
  {
    uint8_t *reg = (uint8_t*)run + run->io.data_offset;
    *reg = line_status;
  }
  else if (run->io.port == MSR)
  {
    uint8_t *reg = (uint8_t*)run + run->io.data_offset;
    *reg = modem_status;
  }
  else
  {
    //dump_io(run);
    //errx(1, "not implemented\n");
  }
}

void handle_serial_io(struct kvm_run *run)
{
  //write message on serial port
  if (run->io.direction == KVM_EXIT_IO_OUT)
    handle_out(run);
  else
  {
    handle_in(run);
  }

}
