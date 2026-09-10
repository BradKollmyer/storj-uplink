// Local QUIC wire-compatibility helper. Uses Storj's real Go listener and
// certificate validation. No satellite, access grant, or live service required.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"storj.io/common/identity"
	"storj.io/common/peertls/tlsopts"
	"storj.io/common/rpc/quic"
)

func main() {
	// Bound the helper even if the test process disappears.
	time.AfterFunc(30*time.Second, func() { os.Exit(1) })
	ident, err := identity.NewFullIdentity(context.Background(), identity.NewCAOptions{Difficulty: 0, Concurrency: 1})
	must(err)
	opts, err := tlsopts.NewOptions(ident, tlsopts.Config{PeerIDVersions: "*"}, nil)
	must(err)
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(err)
	listener, err := quic.NewListener(udp, opts.ServerTLSConfig(), nil)
	must(err)
	defer listener.Close()
	fmt.Printf("%s@%s\n", ident.ID, listener.Addr())
	conn, err := listener.Accept()
	must(err)
	defer conn.Close()
	// Echo a large byte stream, including DRPC frames, to verify framing is
	// passed unmodified. Wait for client close before closing the Go session.
	_, err = io.Copy(conn, conn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
