// Local compatibility test using Storj's actual Noise configuration and noiseconn.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/jtolio/noiseconn"
	"storj.io/common/identity"
	"storj.io/common/pb"
	"storj.io/common/rpc/noise"
)

func main() {
	time.AfterFunc(30*time.Second, func() { os.Exit(1) })
	protocol, err := strconv.Atoi(os.Args[1])
	must(err)
	ident, err := identity.NewFullIdentity(context.Background(), identity.NewCAOptions{Difficulty: 0, Concurrency: 1})
	must(err)
	cfg, err := noise.GenerateServerConf(pb.NoiseProtocol(protocol), ident)
	must(err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	defer listener.Close()
	fmt.Printf("%s %x\n", listener.Addr(), cfg.StaticKeypair.Public)
	tcp, err := listener.Accept()
	must(err)
	defer tcp.Close()
	var prefix [8]byte
	_, err = io.ReadFull(tcp, prefix[:])
	must(err)
	if string(prefix[:]) != noise.Header {
		panic("wrong mux prefix")
	}
	conn, err := noiseconn.NewConn(tcp, cfg)
	must(err)
	defer conn.Close()
	// Read the complete application message before echoing, forcing Go to write
	// full 65535-byte plaintext records (65551 ciphertext bytes) in both suites.
	for i := 1; i <= 3; i++ {
		payload := make([]byte, 256*1024+i)
		_, err = io.ReadFull(conn, payload)
		must(err)
		if !bytes.Equal(payload, bytes.Repeat([]byte{byte(i)}, len(payload))) {
			panic("corrupt plaintext")
		}
		_, err = conn.Write(payload)
		must(err)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
