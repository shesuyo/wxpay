package wxpay

import (
	"fmt"
	"testing"
)

var signMap = map[string]string{"appid": "wxd930ea5d5a258f4f", "mch_id": "10000100", "device_info": "1000", "body": "test",
	"nonce_str": "ibuaiVcKdpRxkhJA"}

func TestRandom(b *testing.T) {
	fmt.Println(getNonceStr())
}

func TestSign(b *testing.T) {
	m := make(map[string]string)
	m["appid"] = "wxd930ea5d5a258f4f"
	m["mch_id"] = "10000100"
	m["device_info"] = "1000"
	m["body"] = "test"
	m["nonce_str"] = "ibuaiVcKdpRxkhJA"
	if Sign(m, "192006250b4c09247ec02edce69f6a2d") != "9A0A8659F005D6984697E2CA0A9CF3B7" {
		b.Fail()
		b.Log(Sign(m, "192006250b4c09247ec02edce69f6a2d"))
	}

}

func TestPostUniform(b *testing.T) {
	api := NewAPI("wx20fa041258046bbf", "1299702501", "1v4h5g4s8u1x25tf025f025e10geagf2", "http://www.baidu.com")
	order := api.NewMap()
	order.SetBody("body")
	order.SetOutTradeNo("test2")
	order.SetTotalFee("1")
	order.SetSpbillCreateIP("1.1.1.1")
	order.SetTradeType("APP")
	fmt.Println(UnifiedOrder(order))
}

func Benchmark_SignSelf(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Sign(signMap, "192006250b4c09247ec02edce69f6a2d")
	}
}
