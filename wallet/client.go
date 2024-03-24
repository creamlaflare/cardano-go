package wallet

import (
	"fmt"
	"github.com/creamlaflare/cardano-go/crypto"

	"github.com/creamlaflare/cardano-go"
	"github.com/tyler-smith/go-bip39"
)

// Client provides a clean interface for creating, saving and deleting Wallets.
type Client struct {
	opts    *Options
	network cardano.Network
}

// NewClient builds a new Client using cardano-cli as the default connection
// to the Blockhain.
//
// It uses BadgerDB as the default Wallet storage.
func NewClient(opts *Options) *Client {
	opts.init()
	cl := &Client{opts: opts, network: opts.Node.Network()}
	return cl
}

// Close closes all the resources used by the Client.
func (c *Client) Close() {
	c.opts.DB.Close()
}

// CreateWallet creates a new Wallet using a secure entropy and password,
// returning a Wallet with its corresponding 24 word mnemonic
func (c *Client) CreateWallet(name, password string) (*Wallet, string, error) {
	entropy := newEntropy(entropySizeInBits)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	wallet, err := newWallet(name, password, mnemonic)
	if err != nil {
		return nil, "", err
	}
	wallet.node = c.opts.Node
	wallet.network = c.network
	err = c.opts.DB.Put(wallet)
	if err != nil {
		return nil, "", err
	}
	return wallet, mnemonic, nil
}

func (c *Client) RestoreWallet(name, password, mnemonic string) (*Wallet, error) {
	// Convert mnemonic to seed
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}

	// Create root key from seed
	rootKey := crypto.NewXPrvKeyFromEntropy(entropy, "")

	// Derive the payment key
	paymentKey, err := deriveKeyByPath(rootKey, PaymentPath)
	if err != nil {
		return nil, err
	}

	// Derive the stake key
	stakeKey, err := deriveKeyByPath(rootKey, StakePath)
	if err != nil {
		return nil, err
	}

	// Initialize the wallet
	wallet := &Wallet{
		ID:       newWalletID(),
		Name:     name,
		addrKeys: []crypto.XPrvKey{paymentKey},
		stakeKey: stakeKey,
		rootKey:  rootKey,
		node:     c.opts.Node,
		network:  c.network,
	}

	err = c.opts.DB.Put(wallet)
	if err != nil {
		return nil, err
	}

	return wallet, nil
}

// SaveWallet saves a Wallet in the Client's storage.
func (c *Client) SaveWallet(w *Wallet) error {
	return c.opts.DB.Put(w)
}

// Wallets returns the list of Wallets currently saved in the Client's storage.
func (c *Client) Wallets() ([]*Wallet, error) {
	wallets, err := c.opts.DB.Get()
	if err != nil {
		return nil, err
	}
	for i := range wallets {
		wallets[i].node = c.opts.Node
	}
	return wallets, nil
}

// Wallet returns a Wallet with the given id from the Client's storage.
func (c *Client) Wallet(id string) (*Wallet, error) {
	wallets, err := c.Wallets()
	if err != nil {
		return nil, err
	}
	for _, w := range wallets {
		if w.ID == id || w.Name == id {
			return w, nil
		}
	}
	return nil, fmt.Errorf("wallet %v not found", id)
}

// DeleteWallet removes a Wallet with the given id from the Client's storage.
func (c *Client) DeleteWallet(id string) error {
	return c.opts.DB.Delete(id)
}
