#ifndef SERIAL_H
#define SERIAL_H

#define RBR 0x3F8
#define IER 0x3F9 
#define IIR 0x3FA 
#define LCR 0x3FB
#define MCR 0x3fc
#define LSR 0x3FD 
#define MSR 0x3FE
#define SCR 0x3FF

#define DLAB 0x80
#define BI (1 << 4)
#define UART_IIR_TYPE_BITS  0xc0
#define UART_IIR_NO_INT  0x01
void handle_serial_io(struct kvm_run *run);
void dump_io(struct kvm_run *run);

#endif
