package appstore

import (
	"strconv"
)

const verIOS6 = 6

// The IAPResponse type has the response properties
type IAPResponseIOS6 struct {
	rawReceipt               string      `json:"-"`
	Status                   int         `json:"status"`
	Receipt                  ReceiptIOS6 `json:"receipt"`
	LatestReceiptInfo        ReceiptIOS6 `json:"latest_receipt_info"`
	LatestExpiredReceiptInfo ReceiptIOS6 `json:"latest_expired_receipt_info"`
	LatestReceipt            string      `json:"latest_receipt"`

	// pending_renewal_info in iOS 6 style receipt.
	AutoRenewStatus    int    `json:"auto_renew_status"`
	AutoRenewProductID string `json:"auto_renew_product_id"`
	ExpirationIntent   string `json:"expiration_intent"`
	RetryFlag          string `json:"is_in_billing_retry_period"`

	IsRetryable bool `json:"is_retryable"`
}

func NewIAPResponseIOS6(rc string) *IAPResponseIOS6 {
	return &IAPResponseIOS6{rawReceipt: rc}
}

func (r *IAPResponseIOS6) ToIOS7() *IAPResponseIOS7 {
	ios7 := &IAPResponseIOS7{
		responseVersion: verIOS6,
		rawReceipt:      r.rawReceipt,
		Status:          r.Status,
		Environment:     "",
		LatestReceipt:   r.LatestReceipt,
		IsRetryable:     r.IsRetryable,
	}
	ios7.Receipt = r.Receipt.ToIOS7()
	if r.LatestReceiptInfo.TransactionID != "" {
		ios7.LatestReceiptInfo = []InApp{r.LatestReceiptInfo.ToInApp()}
	}
	if r.LatestExpiredReceiptInfo.TransactionID != "" {
		ios7.LatestReceiptInfo = []InApp{r.LatestExpiredReceiptInfo.ToInApp()}
	}
	if r.AutoRenewProductID != "" {
		ios7.PendingRenewalInfo = []PendingRenewalInfo{{
			AutoRenewProductID: r.AutoRenewProductID,
			AutoRenewStatus:    strconv.Itoa(r.AutoRenewStatus),
			ExpirationIntent:   r.ExpirationIntent,
			RetryFlag:          r.RetryFlag,
		}}
	}
	return ios7
}

// The Receipt type has whole data of receipt
type ReceiptIOS6 struct {
	AppItemID                  string `json:"app_item_id"`
	BundleID                   string `json:"bid"`
	ApplicationVersion         string `json:"bvrs"`
	OriginalApplicationVersion string `json:"original_application_version"`
	OriginalTransactionID      string `json:"original_transaction_id"`
	ProductID                  string `json:"product_id"`
	Quantity                   string `json:"quantity"`
	TransactionID              string `json:"transaction_id"`
	VersionExternalIdentifier  string `json:"version_external_identifier"`
	WebOrderLineItemID         string `json:"web_order_line_item_id"`
	ExpiresDate                string `json:"expires_date_formatted"`
	ExpiresDateMS              string `json:"expires_date"`
	ExpiresDatePST             string `json:"expires_date_formatted_pst"`
	RequestDate
	PurchaseDate
	OriginalPurchaseDate
	IsTrialPeriod        string `json:"is_trial_period"`
	IsInIntroOfferPeriod string `json:"is_in_intro_offer_period"`
	PromotionalOfferID   string `json:"promotional_offer_id"`
	OfferCodeRefName     string `json:"offer_code_ref_name"`
}

func (rc *ReceiptIOS6) ToIOS7() ReceiptIOS7 {
	ios7 := ReceiptIOS7{
		ReceiptType:                "",
		AdamID:                     0,
		DownloadID:                 0,
		AppItemID:                  ToInt64(rc.AppItemID),
		BundleID:                   rc.BundleID,
		ApplicationVersion:         rc.ApplicationVersion,
		OriginalApplicationVersion: rc.OriginalApplicationVersion,
		RequestDate:                rc.RequestDate,
		OriginalPurchaseDate:       rc.OriginalPurchaseDate,
		InApp:                      []InApp{rc.ToInApp()},
	}
	return ios7
}

func (rc *ReceiptIOS6) ToInApp() InApp {
	return InApp{
		Quantity:                  rc.Quantity,
		ProductID:                 rc.ProductID,
		TransactionID:             rc.TransactionID,
		OriginalTransactionID:     rc.OriginalTransactionID,
		VersionExternalIdentifier: rc.VersionExternalIdentifier,
		WebOrderLineItemID:        rc.WebOrderLineItemID,
		PurchaseDate:              rc.PurchaseDate,
		OriginalPurchaseDate:      rc.OriginalPurchaseDate,
		ExpiresDate: ExpiresDate{
			ExpiresDate:    rc.ExpiresDate,
			ExpiresDateMS:  rc.ExpiresDateMS,
			ExpiresDatePST: rc.ExpiresDatePST,
		},
		IsTrialPeriod:        rc.IsTrialPeriod,
		IsInIntroOfferPeriod: rc.IsInIntroOfferPeriod,
		PromotionalOfferID:   rc.PromotionalOfferID,
		OfferCodeRefName:     rc.OfferCodeRefName,
	}
}
