#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <err.h>

#include "serial.h"

static uint8_t line_config = DLAB;
static uint8_t interrupt_enable = 0;
static uint8_t interrupt_identification = UART_IIR_NO_INT;
static uint8_t modem_control = 0;
static uint8_t modem_status = 0;
static uint8_t line_status = 1 << 5 | 1 << 6;
static uint8_t dll = 0;
static uint8_t dlm = 0;
static uint8_t scr = 0;

void dump_io(struct kvm_run *run)
{
  char *direction;
  if (run->io.direction == KVM_EXIT_IO_IN)
    direction = "IN";
  else
    direction = "OUT";
  printf("io: dir: %s port: 0x%x size: %u off: %llu count: %u\n",
      direction, run->io.port, run->io.size, run->io.data_offset, run->io.count);
}

void handle_out(struct kvm_run *run)
{
  if (run->io.port == RBR)
  {
    if (line_config & DLAB)
    {
      uint8_t enable_bit = *((uint8_t*)run + run->io.data_offset);
      dll = enable_bit;
    }
    else
      putchar(*(((char *)run) + run->io.data_offset));
  }
  //Interrupt Enable Register
  else if (run->io.port == IER)
  {

    if (line_config & DLAB)
    {
      uint8_t enable_bit = *((uint8_t*)run + run->io.data_offset);
      dlm = enable_bit & 0x0f;

    }
    else
    {
      uint8_t enable_bit = *((uint8_t*)run + run->io.data_offset);
      interrupt_enable = enable_bit;
    }
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
  else if (run->io.port == SCR)
  {
    uint8_t enable_bit = *((uint8_t*)run + run->io.data_offset);
    scr = enable_bit;
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
    if (line_config & 0x80)
    {
      uint8_t *reg = (uint8_t*)run + run->io.data_offset;
      *reg = dll;
      return;
    }
    if (line_status & BI)
    {
      line_status &= ~BI;
      uint8_t *reg = (uint8_t*)run + run->io.data_offset;
      *reg = 0;
      return;
    }
    //uint8_t *reg = (uint8_t*)run + run->io.data_offset;
    //*reg = getchar();
    //line_status &= ~1;
  }
  else if (run->io.port == IER)
  {
    if (line_config & 0x80)
    {
      uint8_t *reg = (uint8_t*)run + run->io.data_offset;
      *reg = dlm;
    }
    else
    {
      uint8_t *reg = (uint8_t*)run + run->io.data_offset;
      *reg = interrupt_enable;
    }
  }
  else if (run->io.port == IIR)
  {
    uint8_t *reg = (uint8_t*)run + run->io.data_offset;
    *reg = 0;//interrupt_identification | UART_IIR_TYPE_BITS;
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
  else if (run->io.port == SCR)
  {
    uint8_t *reg = (uint8_t*)run + run->io.data_offset;
    *reg = scr;
  }
  else
  {
    //errx(1, "not implemented\n");
  }
}

void handle_serial_io(struct kvm_run *run)
{
  if (run->io.direction == KVM_EXIT_IO_OUT)
    handle_out(run);
  else
  {
    handle_in(run);
  }
}
