package adapter

import "github.com/alfred-hq/dq-vault/lib/adapter/baseadapter"

type BitcoinAdapter struct {
	baseadapter.BitcoinBaseAdapter
}

func NewBitcoinAdapter(seed []byte, derivationPath string, isDev bool) *BitcoinAdapter {
	adapter := new(BitcoinAdapter)
	adapter.Seed = seed
	adapter.DerivationPath = derivationPath
	adapter.IsDev = isDev

	return adapter
}
