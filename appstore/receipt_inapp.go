package appstore

import (
	"time"
)

// ReceiptInApp is struct for in_app field
type ReceiptInApp struct {
	Quantity                  int64
	ProductID                 string
	TransactionID             int64
	OriginalTransactionID     int64
	IsTrialPeriod             bool
	AppItemID                 int64
	VersionExternalIdentifier int64
	WebOrderLineItemID        int64
	PurchaseDate              time.Time
	OriginalPurchaseDate      time.Time
	ExpiresDate               time.Time
	CancellationDate          time.Time
	PromotionalOfferID        string
}

type ReceiptInApps []*ReceiptInApp

func (r ReceiptInApps) IsAutoRenewable() bool {
	for _, v := range r {
		if v.ExpiresDate.IsZero() {
			return false
		}
	}
	return true
}

func (r ReceiptInApps) ByTransactionID(id int64) *ReceiptInApp {
	for _, v := range r {
		if v.TransactionID == id {
			return v
		}
	}
	return nil
}

func (r ReceiptInApps) ByProduct(productID string) ReceiptInApps {
	var matched ReceiptInApps
	for _, v := range r {
		if v.ProductID != productID {
			continue
		}
		matched = append(matched, v)
	}
	return matched
}

func (r ReceiptInApps) TransactionIDs() []int64 {
	var ids []int64
	for _, v := range r {
		ids = append(ids, v.TransactionID)
	}
	return ids
}

func (r ReceiptInApps) TransactionIDsByProduct(productID string) []int64 {
	var matched []int64
	for _, v := range r {
		if v.ProductID != productID {
			continue
		}
		matched = append(matched, v.TransactionID)
	}
	return matched
}

// for auto-renewable
func (r ReceiptInApps) LastExpiresByProductID(productID string) *ReceiptInApp {
	var latest *ReceiptInApp
	for _, v := range r {
		switch {
		case v.ProductID != productID:
			continue
		case latest != nil && latest.ExpiresDate.After(v.ExpiresDate):
			continue
		}
		latest = v
	}
	return latest
}

// for LatestReceiptInfo
func (r ReceiptInApps) LastExpiresByProductIDForLatest(productID string) *ReceiptInApp {
	for i := len(r) - 1; i >= 0; i-- {
		v := r[i]
		if v.ProductID == productID {
			return v
		}
	}
	return nil
}

func (r ReceiptInApps) LastExpiresByTransactionIDs(ids []int64) *ReceiptInApp {
	idMap := make(map[int64]bool)
	for _, id := range ids {
		idMap[id] = true
	}

	var latest *ReceiptInApp
	for _, v := range r {
		_, ok := idMap[v.TransactionID]
		switch {
		case !ok:
			continue
		case latest != nil && latest.ExpiresDate.After(v.ExpiresDate):
			continue
		}
		latest = v
	}
	return latest
}

func (r ReceiptInApps) LastExpiresByTransactionIDsForLatest(ids []int64) *ReceiptInApp {
	idMap := make(map[int64]bool)
	for _, id := range ids {
		idMap[id] = true
	}

	for i := len(r) - 1; i >= 0; i-- {
		v := r[i]
		if _, ok := idMap[v.TransactionID]; ok {
			return v
		}
	}
	return nil
}
