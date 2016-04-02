package wxpay

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"

	"coding.net/moss/yogo/httplib"
)

const (
	DEVICE_INFO_WEB   = "WEB"
	TRADE_TYPE_APP    = "APP"
	TRADE_TYPE_NATIVE = "NATIVE"
	TRADE_TYPE_JSAPI  = "JSAPI"

	URL_UNIFIEDORDER = "https://api.mch.weixin.qq.com/pay/unifiedorder"
	URL_ORDERQUERY   = "https://api.mch.weixin.qq.com/pay/orderquery"
	URL_REFUND       = "https://api.mch.weixin.qq.com/secapi/pay/refund"
	URL_REFUNDQUERY  = "https://api.mch.weixin.qq.com/pay/refundquery"

	RETURN_CODE_SUCCESS = "SUCCESS"
	RETURN_CODE_FAIL    = "FAIL"
	RESULT_CODE_SUCCESS = "SUCCESS"
	RESULT_CODE_FAIL    = "FAIL"
)

func NewAPI(appID, mchID, apiKey, notifyURL string) *APIInfo {
	info := APIInfo{}
	info.AppID = appID
	info.MchID = mchID
	info.ApiKey = apiKey
	info.NotifyURL = notifyURL
	return &info
}

type APIInfo struct {
	AppID     string
	MchID     string
	ApiKey    string
	NotifyURL string
}

func (this *APIInfo) NewMap() *payMap {
	pm := &payMap{}
	pm.m = make(map[string]string)
	pm.info = this
	return pm
}

//订单查询
func OrderQuery(pm *payMap) (map[string]string, error) {
	pm.BasicCheckSet()
	if pm.m["transaction_id"] == "" && pm.m["out_trade_no"] == "" {
		panic("缺少查询订单选填参数transaction_id或者out_trade_no！！！")
	}
	pm.Sign()
	post := httplib.Post(URL_ORDERQUERY)
	post.Body(pm.ToXML())
	xmlStr, err := post.String()
	if err != nil {
		return nil, err
	}
	outXMLMap := XMLToMap(xmlStr, true)
	return outXMLMap, nil
}

//退款
func RefundOrder(pm *payMap) (map[string]string, error) {
	m := pm.m
	pm.BasicCheckSet()
	if m["transaction_id"] == "" && m["out_trade_no"] == "" {
		panic("微信订单号和商户订单号二者选其一填写！")
	}
	if m["out_refund_no"] == "" {
		panic("商户退款单号不能为空！")
	}
	if m["total_fee"] == "" {
		panic("总金额不能为空！")
	}
	if m["refund_fee"] == "" {
		panic("退款金额不能为空！")
	}
	if m["op_user_id"] == "" {
		//默认填写商户号
		m["op_user_id"] = pm.info.MchID
	}
	if m["sign"] == "" {
		m["sign"] = Sign(m, pm.info.ApiKey)
	}

	outXMLMap := make(map[string]string)
	post := httplib.Post(URL_REFUND)
	post.SetTLSClientConfig(MustGetTlsConfiguration())
	post.Body(pm.ToXML())
	xmlStr, err := post.String()
	if err != nil {
		return outXMLMap, err
	}
	outXMLMap = XMLToMap(xmlStr, true)
	if Sign(outXMLMap, pm.info.ApiKey) != outXMLMap["sign"] {
		panic("server return xml sign error")
	}
	return outXMLMap, nil
}

func MustLoadCertificates() (tls.Certificate, *x509.CertPool) {

	privateKeyFile := "conf/wechat_cert/apiclient_key.pem"
	certificateFile := "conf/wechat_cert/apiclient_cert.pem"
	caFile := "conf/wechat_cert/rootca.pem"

	mycert, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		panic(err)
	}

	pem, err := ioutil.ReadFile(caFile)
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pem) {
		panic("Failed appending certs")
	}

	return mycert, certPool

}

func MustGetTlsConfiguration() *tls.Config {
	config := &tls.Config{}
	mycert, certPool := MustLoadCertificates()
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0] = mycert

	config.RootCAs = certPool
	config.ClientCAs = certPool

	config.ClientAuth = tls.RequireAndVerifyClientCert

	//Optional stuff

	//Use only modern ciphers
	config.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}

	//Use only TLS v1.2
	config.MinVersion = tls.VersionTLS12

	//Don't allow session resumption
	config.SessionTicketsDisabled = true
	return config
}

//统一下单
func UnifiedOrder(pm *payMap) (map[string]string, error) {
	m := pm.m
	rMap := make(map[string]string)
	pm.BasicCheckSet()
	if m["notify_url"] == "" {
		m["notify_url"] = pm.info.NotifyURL
	}
	if m["body"] == "" {
		panic("缺少统一支付接口必填参数body！")
	}
	if m["out_trade_no"] == "" {
		panic("缺少统一支付接口必填参数out_trade_no！")
	}
	if m["total_fee"] == "" {
		panic("缺少统一支付接口必填参数total_fee！")
	}
	if m["spbill_create_ip"] == "" {
		panic("缺少统一支付接口必填参数spbill_create_ip！")
	}
	if m["trade_type"] == "" {
		panic("缺少统一支付接口必填参数trade_type！")
	}
	if m["trade_type"] == "JSAPI" && m["openid"] == "" {
		panic("统一支付接口中，缺少必填参数openid！trade_type为JSAPI时，openid为必填参数！")
	}
	if m["trade_type"] == "NATIVE" && m["product_id"] == "" {
		panic("统一支付接口中，缺少必填参数product_id！trade_type为JSAPI时，product_id为必填参数！")
	}
	if m["sign"] == "" {
		m["sign"] = Sign(m, pm.info.ApiKey)
	}
	post := httplib.Post(URL_UNIFIEDORDER)
	post.Body(pm.ToXML())
	xmlStr, err := post.String()
	if err != nil {
		return rMap, err
	}
	outXMLMap := XMLToMap(xmlStr, true)
	if Sign(outXMLMap, pm.info.ApiKey) != outXMLMap["sign"] {
		panic("server return xml sign error")
	}

	if m["trade_type"] == TRADE_TYPE_APP {
		rMap["appid"] = pm.info.AppID
		rMap["partnerid"] = pm.info.MchID
		rMap["prepayid"] = outXMLMap["prepay_id"]
		rMap["package"] = "Sign=WXPay"
		rMap["noncestr"] = getNonceStr()
		rMap["timestamp"] = strconv.Itoa(int(time.Now().Unix()))
		rMap["sign"] = Sign(rMap, pm.info.ApiKey)
	}
	return rMap, nil
}

//退款查询
func RefundQuery(pm *payMap) (map[string]string, error) {
	m := pm.m
	pm.BasicCheckSet()
	if m["transaction_id"] == "" && m["out_trade_no"] == "" && m["out_refund_no"] == "" && m["refund_id"] == "" {
		panic("微信订单号、商户订单号、商户退款单号、微信退款单号四选一！")
	}
	if m["sign"] == "" {
		m["sign"] = Sign(m, pm.info.ApiKey)
	}
	outXMLMap := make(map[string]string)
	post := httplib.Post(URL_REFUNDQUERY)
	post.Body(pm.ToXML())
	xmlStr, err := post.String()
	if err != nil {
		return outXMLMap, err
	}
	outXMLMap = XMLToMap(xmlStr, true)
	if Sign(outXMLMap, pm.info.ApiKey) != outXMLMap["sign"] {
		panic("server return xml sign error")
	}
	return outXMLMap, nil
}

//签名函数，待优化效率。
func Sign(paras map[string]string, apiKey string) string {
	ks := make([]string, 0, len(paras))
	md5New := md5.New()
	bf := bytes.NewBuffer(make([]byte, 0, 200))
	for k, v := range paras {
		if k == "sign" {
			continue
		}
		if strings.Trim(v, " ") == "" {
			continue
		}
		ks = append(ks, k)
	}
	sort.Strings(ks)

	for _, v := range ks {
		bf.WriteString(v)
		bf.WriteByte('=')
		bf.WriteString(paras[v])
		bf.WriteByte('&')
	}
	bf.WriteString("key=")
	bf.WriteString(apiKey)
	md5New.Write(bf.Bytes())
	return fmt.Sprintf("%X", md5New.Sum(nil))
}

//获取32位长度的随机数
func getNonceStr() (nonceStr string) {
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	for i := 0; i < 32; i++ {
		idx := rand.Intn(len(chars) - 1)
		nonceStr += chars[idx : idx+1]
	}
	return
}

//只能处理一层的xml
func XMLToMap(xmlStr string, isIngoreFirst bool) map[string]string {
	m := make(map[string]string)
	p := xml.NewDecoder(strings.NewReader(xmlStr))
	val := ""
	for {
		token, err := p.Token()
		if err != nil {
			break
		}
		switch t := token.(type) {
		case xml.StartElement:
			if isIngoreFirst {
				isIngoreFirst = false
				continue
			}
			val = t.Name.Local
		case xml.CharData:
			if val != "" {
				m[val] = string(t)
			}
		case xml.EndElement:
			val = ""
		}
	}
	return m
}
