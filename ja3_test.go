package ja3

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"

	xtls "github.com/refraction-networking/utls"
)

func TestNewTransport(t *testing.T) {
	http.DefaultTransport = NewTransport(
		WithProxy("http://127.0.0.1:7890"),
		WithClientHelloID(xtls.HelloChrome_133),
	)

	req := newRequest("https://legacy.lmarena.ai/info")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	bts, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	t.Logf("%s, error: %v", bts, err)
}

func TestJa3(t *testing.T) {
	_ = os.Setenv("ALL_PROXY", "socks5://127.0.0.1:7890")

	klw, err := os.OpenFile("./sslkeylogging.log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("os.OpenFile error: %+v", err)
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	// 自定义DialTLSContext函数，此函数会用于创建tcp连接和tls握手
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		//echConf, err := base64.RawStdEncoding.DecodeString("AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA")
		//if err != nil {
		//	return nil, err
		//}

		config := xtls.Config{
			ServerName:   strings.Split(addr, ":")[0],
			KeyLogWriter: klw,
			//EncryptedClientHelloConfigList: echConf,
		}

		// socks5
		//dialConn, err := proxy.Dial(ctx, "tcp", addr)

		// http
		u, _ := url.Parse("http://127.0.0.1:7890")
		d, err := NewProxy(u, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("http proxies error: %+v", err)
		}

		dialConn, err := d.Dial("tcp", addr)

		//var d net.Dialer
		//dialConn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("net.DialTimeout error: %+v", err)
		}
		uTlsConn := xtls.UClient(dialConn, &config, xtls.HelloChrome_133)
		// uTlsConn := tls.Client(dialConn, &config)
		//defer uTlsConn.Close()
		return uTlsConn, err
	}

	// 发送请求
	//sendHttp1(t, tr, "https://tls.browserleaks.com/json")
	//sendHttp2(t, tr, "https://tls.browserleaks.com/json")

	sendHttp2(t, tr, "https://legacy.lmarena.ai/info")
}

func sendHttp1(t *testing.T, tr http.RoundTripper, url string) {
	c := http.Client{
		Transport: tr,
	}
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}

	bts, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	t.Logf("%s, error: %v", bts, err)
}

func sendHttp2(t *testing.T, tr *http.Transport, uri string) {
	urlObj, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(urlObj)

	scheme := urlObj.Scheme
	host := urlObj.Host
	port := urlObj.Port()
	if port == "" {
		if scheme == "" || scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}

	con, err := tr.DialTLSContext(context.Background(), "tcp", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		t.Fatal("DialTLSContext", err)
		return
	}
	tr2 := http2.Transport{}
	h2Con, err := tr2.NewClientConn(con)
	if err != nil {
		t.Fatal("NewClientConn", err)
		return
	}

	req := newRequest(uri)

	resp2, err := h2Con.RoundTrip(req)
	if err != nil {
		t.Fatal("RoundTrip", err)
		return
	}

	bts, err := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	t.Logf("%s, error: %v", bts, err)
}

func newRequest(uri string) *http.Request {
	req, _ := http.NewRequest("GET", uri, nil)
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0")
	req.Header.Set("accept", "*/*")
	req.Header.Set("accept-language", "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6")
	req.Header.Set("cookie", "ph_phc_LG7IJbVJqBsk584rbcKca0D5lV2vHguiijDrVji7yDM_posthog=%7B%22distinct_id%22%3A%22ee459677-955b-4904-a740-9fa3b7d3654a%22%2C%22%24sesid%22%3A%5B1752826574193%2C%2201981c9a-f571-7e44-a8ff-bb62ef653b48%22%2C1752826574193%5D%2C%22%24epp%22%3Atrue%2C%22%24initial_person_info%22%3A%7B%22r%22%3A%22https%3A%2F%2Flmarena.ai%2F%3F__cf_chl_tk%3D0PSrvQmCMsxBXRxXhU14BAsxhlqFgTtb23bU_tq4s2Y-1752234575-1.0.1.1-5RBKcnZZxOuZGUvi4HsPGyVinozbJdLSBBuNVjQ1pds%22%2C%22u%22%3A%22https%3A%2F%2Flmarena.ai%2F%22%7D%7D; __cf_bm=_LcSqg4.6BuUURMGh6D9uPvSW0avU1Oqndl.uvgBXdc-1753409838-1.0.1.1-d3S.QtdasHtJ6V9ceMFyfvsvAb0Ar1ZoM3.sIIu4P51TxpK90j2iyQAWrJFRVtYTwM7fGW3TEzs5289hA7ic1HdaqzMMrZUHp1GBY0w8QHU; SERVERID=S5|aILqD; cf_clearance=Qzjf21gWVTi20_RXfCQrLd4YhZWAM3_gHQ6IN_e_Zf4-1753410062-1.2.1.1-gYMYff4rQZ1x4SFDAJBu6verMRAI5WVb28UjekM9C8GQWDs0okFn7Hl089dNLWvCpDh5cVeZtg1_e.8DN9DcWC5agoNjBY3ogSbbiuJiIc555TOYovuZ34UrS8_JCBSLuaMRIVSNxjZXMEhWTieGCfhg6oX2YiT32e3jVbdKYc3ltsSB3Y4hWKLqvFhGkIgvj8cpzzRLUxe96nNk6lhBBhNinQcHgdU9a8k.UqDPOmI")
	//req.Header.Set("accept-encoding", "gzip, deflate, br, zstd")
	return req
}
