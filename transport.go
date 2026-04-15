package ja3

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
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

func matchHost(pattern, host string) bool {
	host = stripPort(host)
	pattern = stripPort(pattern)

	ok, err := path.Match(pattern, host)
	if err != nil {
		return false
	}
	return ok
}

func stripPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return h
}

type roundTripper struct {
	originalTransport *http.Transport
	helloId           xtls.ClientHelloID
	proxies           string

	mu    sync.RWMutex
	rules map[string]*http.Transport
}

func (tripper *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if tripper.rules == nil {
		return tripper.originalTransport.RoundTrip(req)
	}

	host := req.URL.Host
	transport := tripper.findTransport(host)
	return transport.RoundTrip(req)
}

func (tripper *roundTripper) Rule(pattern string, idleConnTimeout int) {
	if idleConnTimeout < 0 {
		return
	}

	transport := tripper.originalTransport.Clone()
	transport.IdleConnTimeout = time.Duration(idleConnTimeout) * time.Second
	transport.DisableKeepAlives = idleConnTimeout == 0
	//transport.ForceAttemptHTTP2 = idleConnTimeout != 0
	dialTLS(tripper, transport)
	tripper.rules[pattern] = transport
}

func (tripper *roundTripper) CloseIdleConnections() {
	tripper.mu.Lock()
	defer tripper.mu.Unlock()

	for _, transport := range tripper.rules {
		transport.CloseIdleConnections()
	}

	tripper.originalTransport.CloseIdleConnections()
}

func (tripper *roundTripper) CloseIdleConnection(pattern string) {
	if pattern == "" {
		tripper.originalTransport.CloseIdleConnections()
		return
	}

	for rule, transport := range tripper.rules {
		if matchHost(pattern, rule) {
			transport.CloseIdleConnections()
		}
	}
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

func WithOriginalTransport(tr *http.Transport) TransportArgs {
	return func(tripper *roundTripper) {
		tripper.originalTransport = tr
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

func NewTransport(args ...TransportArgs) http.RoundTripper {
	var tripper = &roundTripper{
		rules: make(map[string]*http.Transport),
	}

	if args != nil {
		for _, apply := range args {
			apply(tripper)
		}
	}

	if tripper.originalTransport == nil {
		tripper.originalTransport = http.DefaultTransport.(*http.Transport).Clone()
	}

	// 兼容 http 请求代理
	tripper.originalTransport.Proxy = func(req *http.Request) (*url.URL, error) {
		if req.URL.Scheme == "http" {
			proxies := tripper.getProxy("")
			if proxies != "" {
				return url.Parse(proxies)
			}
		}
		return nil, nil
	}

	return dialTLS(tripper, tripper.originalTransport)
}

func dialTLS(tripper *roundTripper, transport *http.Transport) http.RoundTripper {
	// https tls 请求
	dialTLSContext := func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		config := xtls.Config{
			ServerName: strings.Split(addr, ":")[0],
		}

		if cfg == nil {
			cfg = &tls.Config{}
		}

		var dialConn net.Conn
		if proxies := tripper.getProxy("tls"); proxies != "" {
			var err error
			dialConn, err = newConn(ctx, proxies, addr, cfg)
			if err != nil {
				return nil, err
			}
		}

		if dialConn == nil {
			var d net.Dialer
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, fmt.Errorf("net.DialTimeout error: %+v", err)
			}
			dialConn = conn
		}

		uTlsConn := xtls.UClient(dialConn, &config, tripper.helloId)
		//defer uTlsConn.Close()
		return uTlsConn, nil
	}

	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialTLSContext(ctx, network, addr, transport.TLSClientConfig)
	}

	h2, err := http2.ConfigureTransports(transport)
	if err != nil {
		panic(fmt.Errorf("error configuring H2 transport: %+v", err))
	}

	h2.ConnPool = nil
	h2.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		return dialTLSContext(ctx, network, addr, cfg)
	}

	return tripper
}

func (tripper *roundTripper) getProxy(schema string) string {
	proxies := tripper.proxies
	if proxies == "" {
		envConfig := FromEnvironment()
		if schema == "tls" {
			if envConfig.HTTPSProxy != "" {
				proxies = envConfig.HTTPSProxy
			}
		}

		if envConfig.HTTPProxy != "" {
			proxies = envConfig.HTTPProxy
		}

		if proxies == "" && envConfig.ALLProxy != "" {
			proxies = envConfig.ALLProxy
		}
	}
	return proxies
}

func (tripper *roundTripper) findTransport(host string) http.RoundTripper {
	tripper.mu.RLock()
	defer tripper.mu.RUnlock()

	for rule, transport := range tripper.rules {
		if matchHost(rule, host) {
			return transport
		}
	}

	return tripper.originalTransport
}

func newConn(ctx context.Context, proxies, addr string, cfg *tls.Config) (dialConn net.Conn, err error) {
	u, err := url.Parse(proxies)
	if err != nil {
		return
	}

	switch u.Scheme {
	case "http", "https":
		var d proxy.Dialer
		d, err = NewWithConfig(u, proxy.Direct, &Config{
			Context:            ctx,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			ServerName:         cfg.ServerName,
		})
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

		var d proxy.Dialer
		d, err = proxy.SOCKS5("tcp", canonicalAddr(u), auth, proxy.Direct)
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
