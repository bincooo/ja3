package ja3

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/net/http2"
	"golang.org/x/net/idna"
	"golang.org/x/net/proxy"

	xtls "github.com/refraction-networking/utls"
)

var portMap = map[string]string{
	"http":    "80",
	"https":   "443",
	"socks5":  "1080",
	"socks5h": "1080",
}

type roundTripper struct {
	originalTransport *http.Transport
	tlsDial           func(req *http.Request) (*xtls.UConn, error)
	helloId           xtls.ClientHelloID
	proxies           string

	mu          sync.Mutex
	idleClosers []func()
}

type TransportArgs func(tripper *roundTripper)

func WithClientHelloID(helloId xtls.ClientHelloID) TransportArgs {
	return func(tripper *roundTripper) {
		tripper.helloId = helloId
	}
}

func WithProxy(proxies string) TransportArgs {
	return func(tripper *roundTripper) {
		tripper.proxies = proxies
	}
}

func idnaASCIIFromURL(url *url.URL) string {
	addr := url.Hostname()
	if v, err := idnaASCII(addr); err == nil {
		addr = v
	}
	return addr
}

// Is returns whether s is ASCII.
func Is(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func idnaASCII(v string) (string, error) {
	if Is(v) {
		return v, nil
	}
	return idna.Lookup.ToASCII(v)
}

// canonicalAddr returns url.Host but always with a ":port" suffix.
func canonicalAddr(url *url.URL) string {
	port := url.Port()
	if port == "" {
		port = portMap[url.Scheme]
	}
	return net.JoinHostPort(idnaASCIIFromURL(url), port)
}

func (tripper *roundTripper) addCloser(yield func()) {
	tripper.mu.Lock()
	defer tripper.mu.Unlock()
	tripper.idleClosers = append(tripper.idleClosers, yield)
}

func (tripper *roundTripper) CloseIdleConnections() {
	tripper.mu.Lock()
	defer tripper.mu.Unlock()

	if tripper.idleClosers == nil || len(tripper.idleClosers) == 0 {
		return
	}

	for _, apply := range tripper.idleClosers {
		apply()
	}
}

func (tripper *roundTripper) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	dialConn, err := tripper.tlsDial(req)
	if err != nil {
		return
	}
	//defer dialConn.Close()

	err = dialConn.Handshake()
	if err != nil {
		return
	}

	protocol := dialConn.ConnectionState().NegotiatedProtocol
	switch protocol {
	case "http/1.1":
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1
		err = req.Write(dialConn)
		if err != nil {
			_ = dialConn.Close()
			return
		}
		tripper.addCloser(func() { dialConn.Close() })
		return http.ReadResponse(bufio.NewReader(dialConn), req)

	case "h2":
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0
		tr := http2.Transport{}
		var conn *http2.ClientConn
		conn, err = tr.NewClientConn(dialConn)
		if err != nil {
			_ = dialConn.Close()
			return
		}
		tripper.addCloser(func() { dialConn.Close() })
		return conn.RoundTrip(req)

	default:
		return tripper.originalTransport.RoundTrip(req)
	}
}

func NewTransport(args ...TransportArgs) http.RoundTripper {
	var tripper = &roundTripper{}
	if args != nil {
		for _, apply := range args {
			apply(tripper)
		}
	}

	tripper.originalTransport = http.DefaultTransport.(*http.Transport).Clone()
	tripper.tlsDial = func(req *http.Request) (*xtls.UConn, error) {
		addr := canonicalAddr(req.URL)
		config := xtls.Config{
			ServerName: strings.Split(addr, ":")[0],
		}

		var dialConn net.Conn
		proxies := tripper.getProxy(req)
		if proxies != "" {
			var err error
			dialConn, err = newConn(proxies, req)
			if err != nil {
				return nil, err
			}
		}

		if dialConn == nil {
			var d net.Dialer
			conn, err := d.DialContext(req.Context(), "tcp", addr)
			if err != nil {
				return nil, fmt.Errorf("net.DialTimeout error: %+v", err)
			}
			dialConn = conn
		}

		uTlsConn := xtls.UClient(dialConn, &config, tripper.helloId)
		// uTlsConn := tls.Client(dialConn, &config)
		//defer uTlsConn.Close()
		return uTlsConn, nil
	}

	return tripper
}

func (tripper *roundTripper) getProxy(req *http.Request) string {
	proxies := tripper.proxies
	if proxies == "" {
		envConfig := FromEnvironment()
		switch req.URL.Scheme {
		case "http":
			if envConfig.HTTPProxy != "" {
				proxies = envConfig.HTTPProxy
			}
		case "https":
			if envConfig.HTTPSProxy != "" {
				proxies = envConfig.HTTPSProxy
			}
		}

		if proxies == "" && envConfig.ALLProxy != "" {
			proxies = envConfig.ALLProxy
		}
	}
	return proxies
}

func newConn(proxies string, req *http.Request) (dialConn net.Conn, err error) {
	addr := canonicalAddr(req.URL)
	u, err := url.Parse(proxies)
	if err != nil {
		return
	}

	switch u.Scheme {
	case "http", "https":
		d, err := NewWithConfig(u, proxy.Direct, &Config{Context: req.Context()})
		if err != nil {
			err = fmt.Errorf("http proxies error: %+v", err)
		}

		dialConn, err = d.Dial("tcp", addr)
		if err != nil {
			err = fmt.Errorf("proxy.Dial error: %+v", err)
		}

	case "socks5", "socks5h":
		// socks5
		var auth *proxy.Auth
		if u.User != nil {
			password, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: password}
		}

		d, err := proxy.SOCKS5("tcp", canonicalAddr(u), auth, proxy.Direct)
		if err != nil {
			err = fmt.Errorf("proxy.SOCKS5 error: %+v", err)
		}

		dialConn, err = d.Dial("tcp", addr)
		if err != nil {
			err = fmt.Errorf("proxy.Dial error: %+v", err)
		}

	default:
		err = fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
	}

	return
}
