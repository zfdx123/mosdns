package ngtip

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Request struct {
	ApiKey          string `json:"apikey"`
	Resource        string `json:"resource"`
	Lang            string `json:"lang"`
	RealtimeVerdict bool   `json:"realtime_verdict"`
}

// RespCloud https://api.threatbook.cn/v3/scene/dns # 支持IP和域名
type RespCloud struct {
	Data struct {
		IPS map[string]struct {
			IsMalicious bool `json:"is_malicious"`
		} `json:"ips"`
		Domains map[string]struct {
			IsMalicious bool `json:"is_malicious"`
		} `json:"domains"`
	} `json:"data"`
	ResponseCode int    `json:"response_code"`
	VerboseMsg   string `json:"verbose_msg"`
}

// RespCloud https://api.threatbook.cn/v3/scene/ip_reputation # 仅支持IP
//type RespCloud struct {
//	Data []map[string]struct {
//		IsMalicious bool `json:"is_malicious"`
//	} `json:"data"`
//	ResponseCode int    `json:"response_code"`
//	VerboseMsg   string `json:"verbose_msg"`
//}

// RespTIP 本地NG—TIP 微步情报网关返回
// http://ip:8090/tip_api/v5/dns 似乎查不到ip??
// http://ip:8090/tip_api/v5/ip ip单独查询
// 返回结构体统一
type RespTIP struct {
	Data []struct {
		Ioc          string `json:"ioc"`
		Intelligence []struct {
			IsMalicious bool `json:"is_malicious"`
		} `json:"intelligence"`
	} `json:"data"`
	ResponseCode int    `json:"response_code"`
	VerboseMsg   string `json:"verbose_msg"`
}

type Args struct {
	Api            string `yaml:"api"`
	Key            string `yaml:"key"`
	IsCloud        bool   `yaml:"is_cloud"`
	Timeout        uint   `yaml:"timeout"`
	CacheTTL       uint   `yaml:"cache_ttl"`
	WhitelistFile  string `yaml:"whitelist_file"`
	ReloadInterval uint   `yaml:"reload_interval"`
}

func makeNXDOMAIN(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeNameError)
	m.Authoritative = true
	return m
}

func checkBatch(client *http.Client, uri string, apiKey string, isCloud bool, iocs []string) (map[string]bool, error) {
	result := make(map[string]bool)
	if len(iocs) == 0 {
		return result, nil
	}

	var req *http.Request
	if isCloud {
		var err error
		// 构建查询参数
		params := url.Values{}
		params.Set("apikey", apiKey)
		params.Set("resource", strings.Join(iocs, ","))
		params.Set("lang", "zh")
		params.Set("realtime_verdict", "true") // 注意：布尔值需要转换为字符串

		// 构建带查询参数的URL
		targetURL := uri + "?" + params.Encode()

		// 创建GET请求（注意：GET请求没有请求体）
		req, err = http.NewRequest("GET", targetURL, nil)
		if err != nil {
			return nil, err
		}
	} else {
		body := Request{
			ApiKey:          apiKey,
			Resource:        strings.Join(iocs, ","),
			Lang:            "zh",
			RealtimeVerdict: true,
		}

		buf, err := json.Marshal(body)
		fmt.Println(string(buf))
		if err != nil {
			return nil, err
		}

		req, err = http.NewRequest("POST", uri, bytes.NewReader(buf))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return result, nil
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	fmt.Println(string(raw))

	if isCloud {
		// ===== ② 回退解析 Cloud 版本 =====
		var cloud RespCloud
		if err := json.Unmarshal(raw, &cloud); err == nil && cloud.ResponseCode == 0 {
			for ip, item := range cloud.Data.IPS {
				result[ip] = item.IsMalicious
			}
			for ioc, intel := range cloud.Data.Domains {
				result[ioc] = intel.IsMalicious
			}
			fmt.Println(result)
			return result, nil
		} else {
			fmt.Println(err.Error())
		}
	} else {
		// ===== ① 尝试解析 TIP 版本 =====
		var tip RespTIP
		if err := json.Unmarshal(raw, &tip); err == nil && tip.ResponseCode == 0 {
			for _, d := range tip.Data {
				if len(d.Intelligence) > 0 {
					result[d.Ioc] = d.Intelligence[0].IsMalicious
				}
			}
			return result, nil
		}
	}

	return nil, nil
}

func newHTTPClient(timeoutMs uint) *http.Client {
	return &http.Client{
		Timeout: time.Duration(timeoutMs) * time.Millisecond,
	}
}
