# My-Qemu

This project is small linux VM launcher using KVM API

## Getting Started

To begin with this project you just could clone it from github.

### Prerequisites

To make it work you need:
- capstone
- KVM module

### Compile

To compile the project:

```
make
```

It will create a binary called my-kvm

### How to use this debugger

Launch it:

```
./mygdb -m $size-ram --initrd $initrd bzImage opt=value ...
```

-m Set the size of the Vm's RAM it is optional the default size is 1 << 30

--initrd get the path of the initrd image it is optional

You can give some kernel command line argument after the bzImage


## Authors

* **Clement Magnard** - [Deltova](https://github.com/deltova)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
