package veneur

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"sync"

	"github.com/Sirupsen/logrus"
)

// ListeningAddr implements the net.Addr interface and gets
// deserialized from the YAML config file by interpreting it as a URL,
// where the Scheme corresponds to the "net" argument to net.Listen,
// and the host&port or path are the "laddr" arg.
//
// Valid address examples are:
//   - udp6://127.0.0.1:8000
//   - unix:///tmp/foo.sock
//   - tcp://127.0.0.1:9002
type ListeningAddr struct {
	resolvedAddr net.Addr
}

// ResolveAddr takes a URL-style listen address specification,
// resolves it and returns a ListeningAddr that corresponds to the
// string. If any error (in URL decoding, destructuring or resolving)
// occurs, ResolveAddr returns the respective error.
func ResolveAddr(str string) (a *ListeningAddr, err error) {
	var u *url.URL

	u, err = url.Parse(str)
	if err != nil {
		return
	}
	var addr net.Addr
	switch u.Scheme {
	case "unix", "unixgram", "unixpacket":
		addr, err = net.ResolveUnixAddr(u.Scheme, u.Path)
		if err != nil {
			return
		}
		a = &ListeningAddr{addr}
	case "tcp6", "tcp4", "tcp":
		addr, err = net.ResolveTCPAddr(u.Scheme, u.Host)
		if err != nil {
			return
		}
		a = &ListeningAddr{addr}
	case "udp6", "udp4", "udp":
		addr, err = net.ResolveUDPAddr(u.Scheme, u.Host)
		if err != nil {
			return
		}
		a = &ListeningAddr{addr}
	default:
		err = fmt.Errorf("unknown address family %q on address %q", u.Scheme, u.String())
		return
	}
	return
}

// Addr returns the resolved net.Addr object for a ListeningAddr. If
// the ListeningAddr was constructed and returned by ResolveAddr,
// users should expect Addr to return non-nil.
func (a *ListeningAddr) Addr() net.Addr {
	return a.resolvedAddr
}

// StartStatsd spawns a goroutine that listens for metrics in statsd
// format on the address a. As this is a setup routine, if any error
// occurs, it halts the program.
func (a *ListeningAddr) StartStatsd(s *Server, packetPool *sync.Pool) {
	switch addr := a.resolvedAddr.(type) {
	case *net.UDPAddr:
		startStatsdUDP(s, addr, packetPool)
	case *net.TCPAddr:
		startStatsdTCP(s, addr, packetPool)
	default:
		log.Fatalf("Can't listen on %v: only TCP and UDP are supported", a)
	}
}

func startStatsdUDP(s *Server, addr *net.UDPAddr, packetPool *sync.Pool) {
	for i := 0; i < s.numReaders; i++ {
		go func() {
			defer func() {
				ConsumePanic(s.Sentry, s.Statsd, s.Hostname, recover())
			}()
			// each goroutine gets its own socket
			// if the sockets support SO_REUSEPORT, then this will cause the
			// kernel to distribute datagrams across them, for better read
			// performance
			sock, err := NewSocket(addr, s.RcvbufBytes, s.numReaders != 1)
			if err != nil {
				// if any goroutine fails to create the socket, we can't really
				// recover, so we just blow up
				// this probably indicates a systemic issue, eg lack of
				// SO_REUSEPORT support
				log.WithError(err).Fatal("Error listening for UDP metrics")
			}
			log.WithField("address", addr).Info("Listening for UDP metrics")
			s.ReadMetricSocket(sock, packetPool)
		}()
	}
}

func startStatsdTCP(s *Server, addr *net.TCPAddr, packetPool *sync.Pool) {
	var listener net.Listener
	var err error

	listener, err = net.ListenTCP("tcp", addr)
	if err != nil {
		log.WithError(err).Fatal("Error listening for TCP connections")
	}

	go func() {
		<-s.shutdown
		// TODO: the socket is in use until there are no goroutines blocked in Accept
		// we should wait until the accepting goroutine exits
		err := listener.Close()
		if err != nil {
			log.WithError(err).Warn("Ignoring error closing TCP listener")
		}
	}()

	mode := "unencrypted"
	if s.tlsConfig != nil {
		// wrap the listener with TLS
		listener = tls.NewListener(listener, s.tlsConfig)
		if s.tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
			mode = "authenticated"
		} else {
			mode = "encrypted"
		}
	}

	log.WithFields(logrus.Fields{
		"address": addr, "mode": mode,
	}).Info("Listening for TCP connections")

	go func() {
		defer func() {
			ConsumePanic(s.Sentry, s.Statsd, s.Hostname, recover())
		}()
		s.ReadTCPSocket(listener)
	}()
}
