package tapirx

import (
	"fmt"
	"sync"
)

// AssetSet refers to a set of Assets.
type AssetSet struct {
	sync.Mutex
	assets map[string]*Asset
	C      chan Asset
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

// Print renders an AssetSet to standard output.
func (a *AssetSet) String() string {
	a.Lock()
	defer a.Unlock()

	return fmt.Sprint(a.assets)
}

// ConsumeAssets consumes Assets from a channel and safely adds them to the AssetSet.
func (a *AssetSet) ConsumeAssets() {
	for asset := range a.C {
		fmt.Printf("AssetSet worker got asset %v\n", asset)
		a.Add(&asset)
	}
}

// NewAssetSet creates a new empty AssetSet.
func NewAssetSet() *AssetSet {
	set := &AssetSet{}
	set.assets = make(map[string]*Asset)
	set.C = make(chan Asset)
	return set
}
