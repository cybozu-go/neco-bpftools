# Neco-bpftools

Neco-bpftools contains utility tools using eBPF. 

## Available tools

### socket-tracer

Socket-tracer traces `socket` system call by specified socket family.
Please see [socket(2)](https://man7.org/linux/man-pages/man2/socket.2.html).

```console
$ socket-tracer -h
trace socket syscall

Usage:
  socket-tracer [flags]

Flags:
  -f, --family man socket   Family value for socket system call. See man socket. Accepts AF_* or number
  -h, --help                help for socket-tracer
```

## License

Neco-bpftools licensed under GNU General Public License, Version 2.
