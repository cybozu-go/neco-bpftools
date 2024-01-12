package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -type event bpf ../../bpf/trace_enter_socket.c -g -- -I../../bpf/include

func TraceEnterSocket(family int) error {
	ctx := context.Background()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	obj := bpfObjects{}
	if err := loadBpfObjects(&obj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  1024 * 1024 * 256,
		},
	}); err != nil {
		return err
	}
	defer obj.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_socket", obj.TraceEnterSocket, nil)
	if err != nil {
		return err
	}
	defer tp.Close()

	key := uint32(0)
	value := uint32(family)
	if err := obj.TargetFamily.Update(&key, &value, ebpf.UpdateAny); err != nil {
		logger.ErrorContext(ctx, "failed to update TargetFamily", slog.Int("family", family))
		return err
	}

	rb, err := ringbuf.NewReader(obj.EventRb)
	if err != nil {
		return err
	}
	defer rb.Close()

	go func() {
		<-ctrlC
		logger.WarnContext(ctx, "Signal received.. Close ringbuffer.")
		if err := rb.Close(); err != nil {
			panic(err)
		}
	}()

	var event bpfEvent
	for {
		record, err := rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				logger.ErrorContext(ctx, "ringbuffer is closed. exit")
				return nil
			}
			logger.ErrorContext(ctx, "failed to read from ringbuffer", slog.Any("error", err))
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.ErrorContext(ctx, "failed to parse data", slog.Any("error", err))
			continue
		}

		fmt.Printf("{\"pid\": %d,\"command\": \"%s\"}\n", event.Pid, unix.ByteSliceToString(event.Comm[:]))
	}
}

func ParseFamily(family string) (int, error) {

	n, err := strconv.Atoi(family)
	if err != nil {
		if !strings.Contains(family, "AF_") {
			return 0, fmt.Errorf("invalid family value. family must match AF_*.")
		}
		return parseFamily(family)

	}
	return n, nil
}

func parseFamily(family string) (int, error) {
	switch family {
	case "AF_ALG":
		return syscall.AF_ALG, nil
	case "AF_APPLETAL":
		return syscall.AF_APPLETALK, nil
	case "AF_ASH":
		return syscall.AF_ASH, nil
	case "AF_ATMPVC":
		return syscall.AF_ATMPVC, nil
	case "AF_ATMSVC":
		return syscall.AF_ATMSVC, nil
	case "AF_AX25":
		return syscall.AF_AX25, nil
	case "AF_BLUETOOTH":
		return syscall.AF_BLUETOOTH, nil
	case "AF_BRIDGE":
		return syscall.AF_BRIDGE, nil
	case "AF_CAIF":
		return syscall.AF_CAIF, nil
	case "AF_CAN":
		return syscall.AF_CAN, nil
	case "AF_DECnet":
		return syscall.AF_DECnet, nil
	case "AF_ECONET":
		return syscall.AF_ECONET, nil
	case "AF_FILE":
		return syscall.AF_FILE, nil
	case "AF_IEEE80215":
		return syscall.AF_IEEE802154, nil
	case "AF_INET":
		return syscall.AF_INET, nil
	case "AF_INET6":
		return syscall.AF_INET6, nil
	case "AF_IPX":
		return syscall.AF_IPX, nil
	case "AF_IRDA":
		return syscall.AF_IRDA, nil
	case "AF_ISDN":
		return syscall.AF_ISDN, nil
	case "AF_IUCV":
		return syscall.AF_IUCV, nil
	case "AF_KEY":
		return syscall.AF_KEY, nil
	case "AF_LLC":
		return syscall.AF_LLC, nil
	case "AF_LOCAL":
		return syscall.AF_LOCAL, nil
	case "AF_MAX":
		return syscall.AF_MAX, nil
	case "AF_NETBEUI":
		return syscall.AF_NETBEUI, nil
	case "AF_NETLINK":
		return syscall.AF_NETLINK, nil
	case "AF_NETROM":
		return syscall.AF_NETROM, nil
	case "AF_PACKET":
		return syscall.AF_PACKET, nil
	case "AF_PHONET":
		return syscall.AF_PHONET, nil
	case "AF_PPPOX":
		return syscall.AF_PPPOX, nil
	case "AF_RDS":
		return syscall.AF_RDS, nil
	case "AF_ROSE":
		return syscall.AF_ROSE, nil
	case "AF_ROUTE":
		return syscall.AF_ROUTE, nil
	case "AF_RXRPC":
		return syscall.AF_RXRPC, nil
	case "AF_SECURITY":
		return syscall.AF_SECURITY, nil
	case "AF_SNA":
		return syscall.AF_SNA, nil
	case "AF_TIPC":
		return syscall.AF_TIPC, nil
	case "AF_UNIX":
		return syscall.AF_UNIX, nil
	case "AF_UNSPEC":
		return syscall.AF_UNSPEC, nil
	case "AF_WANPIPE":
		return syscall.AF_WANPIPE, nil
	case "AF_X25":
		return syscall.AF_X25, nil
	default:
		return 0, fmt.Errorf("invalid family %s", family)
	}
}
