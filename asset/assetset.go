package asset

import (
	"fmt"
	"sync"
)

// AssetSet refers to a set of Assets.
type AssetSet struct {
	sync.Mutex
	assets map[string]*Asset
}

// Add adds an asset to the AssetSet.
func (a *AssetSet) Add(asset *Asset) {
	a.Lock()
	defer a.Unlock()

	a.assets[asset.MACAddress] = asset
}

// Remove removes an asset from the AssetSet.
func (a *AssetSet) Remove(asset *Asset) {
	a.Lock()
	defer a.Unlock()

	delete(a.assets, asset.MACAddress)
}

// NewAssetSet creates a new empty AssetSet.
func NewAssetSet(C <-chan Asset) *AssetSet {
	set := &AssetSet{}
	set.assets = make(map[string]*Asset)
	go func() {
		// read Assets from the input channel forever.
		for asset := range C {
			fmt.Printf("Got an asset: %v\n", asset)
			set.Add(&asset)
		}
	}()
	return set
}
