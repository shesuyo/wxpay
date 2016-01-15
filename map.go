package wxpay

type payMap struct {
	m    map[string]string
	info *APIInfo
}

//appid mch_id nonce_str
func (this *payMap) BasicCheckSet() {
	m := this.m
	if m["appid"] == "" {
		m["appid"] = this.info.AppID
	}
	if m["mch_id"] == "" {
		m["mch_id"] = this.info.MchID
	}
	if m["nonce_str"] == "" {
		m["nonce_str"] = getNonceStr()
	}
}

func (this *payMap) Sign() {
	this.m["sign"] = Sign(this.m, this.info.ApiKey)
}

func (this *payMap) SetAppID(appID string) {
	this.m["appid"] = appID
}

func (this *payMap) SetMchID(mchID string) {
	this.m["mch_id"] = mchID
}

func (this *payMap) SetDeviceInfo(val string) {
	this.m["device_info"] = val
}

func (this *payMap) SetNonceStr(val string) {
	this.m["nonce_str"] = val
}

func (this *payMap) SetSign(val string) {
	this.m["sign"] = val
}

func (this *payMap) SetBody(val string) {
	this.m["body"] = val
}

func (this *payMap) SetDetail(val string) {
	this.m["detail"] = val
}

func (this *payMap) SetAttach(val string) {
	this.m["attach"] = val
}

func (this *payMap) SetOutTradeNo(val string) {
	this.m["out_trade_no"] = val
}

func (this *payMap) SetFeeType(val string) {
	this.m["fee_type"] = val
}

func (this *payMap) SetTotalFee(val string) {
	this.m["total_fee"] = val
}

func (this *payMap) SetSpbillCreateIP(val string) {
	this.m["spbill_create_ip"] = val
}

func (this *payMap) SetTimeStart(val string) {
	this.m["time_start"] = val
}

func (this *payMap) SetTimeExpire(val string) {
	this.m["time_expire"] = val
}

func (this *payMap) SetGoodsTag(val string) {
	this.m["goods_tag"] = val
}

func (this *payMap) SetNotifyUrl(val string) {
	this.m["notify_url"] = val
}

func (this *payMap) SetTradeType(val string) {
	this.m["trade_type"] = val
}

func (this *payMap) SetProductID(val string) {
	this.m["product_id"] = val
}

func (this *payMap) SetLimitPay(val string) {
	this.m["limit_pay"] = val
}

func (this *payMap) SetOpenID(val string) {
	this.m["openid"] = val
}

func (this *payMap) SetTransactionID(val string) {
	this.m["transaction_id"] = val
}

func (this *payMap) SetOutRefundNo(val string) {
	this.m["out_refund_no"] = val
}

func (this *payMap) SetRefundFee(val string) {
	this.m["refund_fee"] = val
}

func (this *payMap) SetRefundFeeType(val string) {
	this.m["refund_fee_type"] = val
}

func (this *payMap) SetOpUserID(val string) {
	this.m["op_user_id"] = val
}

func (this *payMap) SetBillDate(val string) {
	this.m["bill_date"] = val
}

func (this *payMap) SetBillType(val string) {
	this.m["bill_type"] = val
}

func (this *payMap) SetinterfaceUrl(val string) {
	this.m["interface_url"] = val
}

func (this *payMap) SetExecuteTime(val string) {
	this.m["execute_time_"] = val
}

func (this *payMap) SetReturnCode(val string) {
	this.m["return_code"] = val
}

func (this *payMap) SetReturnMsg(val string) {
	this.m["return_msg"] = val
}

func (this *payMap) SetResultCode(val string) {
	this.m["result_code"] = val
}

func (this *payMap) SetErrCode(val string) {
	this.m["err_code"] = val
}

func (this *payMap) SetErrCodeDes(val string) {
	this.m["err_code_des"] = val
}

func (this *payMap) SetuUserIp(val string) {
	this.m["user_ip"] = val
}

func (this *payMap) SetTime(val string) {
	this.m["time"] = val
}
func (this *payMap) ToXML() (xmlStr string) {
	xmlStr = "<xml>"
	for k, v := range this.m {
		if k == "total_fee" || k == "refund_fee" || k == "execute_time_" {
			xmlStr += "<" + k + ">" + v + "</" + k + ">"
		} else {
			xmlStr += "<" + k + "><![CDATA[" + v + "]]></" + k + ">"
		}

	}
	xmlStr += "</xml>"
	return
}
