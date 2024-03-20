package wallet

import (
	"github.com/creamlaflare/cardano-go"
	cardanocli "github.com/creamlaflare/cardano-go/cardano-cli"
)

type Options struct {
	Node cardano.Node
	DB   DB
}

func (o *Options) init() {
	if o.Node == nil {
		o.Node = cardanocli.NewNode(cardano.Preview)
	}
	if o.DB == nil {
		o.DB = newMemoryDB()
	}
}
