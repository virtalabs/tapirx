package main

import (
	"fmt"
	"sync"

	"github.com/virtalabs/tapirx/asset"
)

// AssetSet refers to a set of Assets.
type AssetSet struct {
	sync.Mutex
	assets []asset.Asset
}

// NewAssetSet creates a new empty AssetSet.
func NewAssetSet(C <-chan asset.Asset) *AssetSet {
	set := &AssetSet{}
	set.assets = make([]asset.Asset, 0, 100)
	go func() {
		// read Assets from the input channel forever.
		for asset := range C {
			fmt.Printf("Got an asset: %v\n", asset)
			set.Lock()
			set.assets = append(set.assets, asset)
			defer set.Unlock()
		}
	}()
	return set
}
