package tapirx

import (
	"fmt"
	"sync"
)

// AssetSet refers to a set of Assets.
type AssetSet struct {
	sync.Mutex
	Assets map[string]*Asset
	C      chan Asset
}

// Add adds an asset to the AssetSet.
func (a *AssetSet) Add(asset *Asset) {
	a.Lock()
	defer a.Unlock()

	a.Assets[asset.MACAddress] = asset
}

// Remove removes an asset from the AssetSet.
func (a *AssetSet) Remove(asset *Asset) {
	a.Lock()
	defer a.Unlock()

	delete(a.Assets, asset.MACAddress)
}

// Print renders an AssetSet to standard output.
func (a *AssetSet) String() string {
	a.Lock()
	defer a.Unlock()

	return fmt.Sprint(a.Assets)
}

// ConsumeAssets consumes Assets from a channel and safely adds them to the AssetSet.
func (a *AssetSet) ConsumeAssets() {
	for asset := range a.C {
		fmt.Printf("AssetSet worker got asset %s\n", asset.String())
		a.Add(&asset)
	}
}

// Len returns the number of Assets in the AssetSet.
func (a *AssetSet) Len() int {
	return len(a.Assets)
}

// NewAssetSet creates a new empty AssetSet.
func NewAssetSet() *AssetSet {
	return &AssetSet{
		Assets: make(map[string]*Asset),
		C:      make(chan Asset),
	}
}
