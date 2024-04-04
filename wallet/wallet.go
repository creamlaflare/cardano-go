package wallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/creamlaflare/cardano-go"
	"github.com/creamlaflare/cardano-go/crypto"
	dpath "github.com/creamlaflare/cardano-go/internal/path"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"github.com/tyler-smith/go-bip39"
)

const (
	entropySizeInBits         = 160
	purposeIndex       uint32 = 1852 + 0x80000000
	coinTypeIndex      uint32 = 1815 + 0x80000000
	accountIndex       uint32 = 0x80000000
	externalChainIndex uint32 = 0x0
	stakingChainIndex  uint32 = 0x02
	walleIDAlphabet           = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

var (
	CardanoStakePath, _ = dpath.Parse("m/1852'/1815'/0'/2/0")
	PaymentPath         = "m/1852'/1815'/0'/0/0" // Example path, adjust if needed
	StakePath           = "m/1852'/1815'/0'/2/0" // Cardano CIP1852 stake path
)

type Wallet struct {
	ID          string
	Name        string
	addrKeys    []crypto.XPrvKey
	stakeKey    crypto.XPrvKey
	rootKey     crypto.XPrvKey
	node        cardano.Node
	network     cardano.Network
	namiAddress *cardano.Address
}

func (w *Wallet) DerivePaymentAndStakeKeysByPath(
	path string,
) (payment crypto.XPrvKey, stake crypto.XPrvKey, err error) {

	rootKey := w.rootKey

	drvPath, err := dpath.Parse(path)
	if err != nil {
		return nil, nil, err
	}

	paymentKey := rootKey
	for _, p := range drvPath {
		paymentKey = paymentKey.Derive(p)
	}

	stakeKey := rootKey
	for _, p := range CardanoStakePath {
		stakeKey = stakeKey.Derive(p)
	}

	return paymentKey, stakeKey, nil
}

// Transfer sends an amount of lovelace to the receiver address and returns the transaction hash
func (w *Wallet) Transfer(receiver cardano.Address, amount *cardano.Value) (*cardano.Hash32, error) {
	// Calculate if the account has enough balance
	balance, err := w.Balance()
	if err != nil {
		return nil, err
	}

	if cmp := balance.Cmp(amount); cmp == -1 || cmp == 2 {
		return nil, fmt.Errorf("Not enough balance, %v > %v", amount, balance)
	}

	// Find utxos that cover the amount to transfer
	pickedUtxos := []cardano.UTxO{}
	utxos, err := w.findUtxos()
	pickedUtxosAmount := cardano.NewValue(0)
	for _, utxo := range utxos {
		if pickedUtxosAmount.Cmp(amount) == 1 {
			break
		}
		pickedUtxos = append(pickedUtxos, utxo)
		pickedUtxosAmount = pickedUtxosAmount.Add(utxo.Amount)
	}

	pparams, err := w.node.ProtocolParams()
	if err != nil {
		return nil, err
	}

	txBuilder := cardano.NewTxBuilder(pparams)

	keys := make(map[int]crypto.XPrvKey)
	for i, utxo := range pickedUtxos {
		for _, key := range w.addrKeys {
			payment, err := cardano.NewKeyCredential(key.PubKey())
			if err != nil {
				return nil, err
			}
			addr, err := cardano.NewEnterpriseAddress(w.network, payment)
			if err != nil {
				return nil, err
			}
			if addr.Bech32() == utxo.Spender.Bech32() {
				keys[i] = key
			}
		}
	}

	if len(keys) != len(pickedUtxos) {
		return nil, errors.New("not enough keys")
	}

	inputAmount := cardano.NewValue(0)
	for _, utxo := range pickedUtxos {
		txBuilder.AddInputs(&cardano.TxInput{TxHash: utxo.TxHash, Index: utxo.Index, Amount: utxo.Amount})
		inputAmount = inputAmount.Add(utxo.Amount)
	}
	txBuilder.AddOutputs(&cardano.TxOutput{Address: receiver, Amount: amount})

	tip, err := w.node.Tip()
	if err != nil {
		return nil, err
	}
	txBuilder.SetTTL(tip.Slot + 1200)
	for _, key := range keys {
		txBuilder.Sign(key.PrvKey())
	}
	changeAddress := pickedUtxos[0].Spender
	txBuilder.AddChangeIfNeeded(changeAddress)
	tx, err := txBuilder.Build()
	if err != nil {
		return nil, err
	}
	return w.node.SubmitTx(tx)
}

// Balance returns the total lovelace amount of the wallet.
func (w *Wallet) Balance() (*cardano.Value, error) {
	balance := cardano.NewValue(0)
	utxos, err := w.findUtxos()
	if err != nil {
		return nil, err
	}
	for _, utxo := range utxos {
		balance = balance.Add(utxo.Amount)
	}
	return balance, nil
}

func (w *Wallet) findUtxos() ([]cardano.UTxO, error) {
	addrs, err := w.Addresses()
	if err != nil {
		return nil, err
	}
	walletUtxos := []cardano.UTxO{}
	for _, addr := range addrs {
		addrUtxos, err := w.node.UTxOs(addr)
		if err != nil {
			return nil, err
		}
		walletUtxos = append(walletUtxos, addrUtxos...)
	}
	return walletUtxos, nil
}

// AddAddress generates a new payment address and adds it to the wallet.
func (w *Wallet) AddAddress() (cardano.Address, error) {
	index := uint32(len(w.addrKeys))
	newKey := w.rootKey.Derive(index)
	w.addrKeys = append(w.addrKeys, newKey)
	payment, err := cardano.NewKeyCredential(newKey.PubKey())
	if err != nil {
		return cardano.Address{}, err
	}
	return cardano.NewEnterpriseAddress(w.network, payment)
}

func (w *Wallet) AddBaseAddress() (cardano.Address, error) {
	index := uint32(len(w.addrKeys))
	newKey := w.rootKey.Derive(index)
	w.addrKeys = append(w.addrKeys, newKey)

	paymentCredential, err := cardano.NewKeyCredential(newKey.PubKey())
	if err != nil {
		return cardano.Address{}, err
	}

	stakingCredential, err := cardano.NewKeyCredential(w.stakeKey.PubKey())
	if err != nil {
		return cardano.Address{}, err
	}

	return cardano.NewBaseAddress(w.network, paymentCredential, stakingCredential)
}

// Addresses returns all wallet's addresss.
func (w *Wallet) Addresses() ([]cardano.Address, error) {
	addresses := make([]cardano.Address, len(w.addrKeys)+1)
	for i, key := range w.addrKeys {
		payment, err := cardano.NewKeyCredential(key.PubKey())
		if err != nil {
			return nil, err
		}
		enterpriseAddr, err := cardano.NewEnterpriseAddress(w.network, payment)
		if err != nil {
			return nil, err
		}
		addresses[i] = enterpriseAddr
	}
	if w.namiAddress != nil {
		addresses = append(addresses, *w.namiAddress)
	} else {
		addr, err := w.GetNamiAddress()
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, *addr)
	}
	return addresses, nil
}

func (w *Wallet) Keys() (crypto.PrvKey, crypto.PrvKey) {
	return w.addrKeys[0].PrvKey(), w.stakeKey.PrvKey()
}

func newWalletID() string {
	id, _ := gonanoid.Generate(walleIDAlphabet, 10)
	return "wallet_" + id
}

func newWallet(name, password string, mnemonic string) (*Wallet, error) {
	entropy, err := bip39.NewEntropy(entropySizeInBits)
	if err != nil {
		return nil, err
	}

	rootKey := crypto.NewXPrvKeyFromEntropy(entropy, password)

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

	wallet := &Wallet{
		ID:       newWalletID(),
		Name:     name,
		addrKeys: []crypto.XPrvKey{paymentKey}, // Assuming you want to start with one key
		stakeKey: stakeKey,
		rootKey:  rootKey, // Storing the root key, adjust based on your need
	}

	return wallet, nil
}

func deriveKeyByPath(rootKey crypto.XPrvKey, path string) (crypto.XPrvKey, error) {
	drvPath, err := dpath.Parse(path)
	if err != nil {
		return crypto.XPrvKey{}, err
	}

	key := rootKey
	for _, p := range drvPath {
		key = key.Derive(p)
	}

	return key, nil
}

func (w *Wallet) GetNamiAddress() (*cardano.Address, error) {
	payment, stake, err := w.DerivePaymentAndStakeKeysByPath("m/1852'/1815'/0'/0/0")
	if err != nil {
		return nil, err
	}
	paymentCreds, err := cardano.NewKeyCredential(payment.XPubKey().PubKey())
	if err != nil {
		return nil, err
	}

	stakeCreds, err := cardano.NewKeyCredential(stake.XPubKey().PubKey())
	if err != nil {
		return nil, err
	}

	addr, err := cardano.NewBaseAddress(w.network, paymentCreds, stakeCreds)
	if err != nil {
		return nil, err
	}

	w.namiAddress = &addr

	return &addr, nil
}

type walletDump struct {
	ID       string
	Name     string
	Keys     []crypto.XPrvKey
	StakeKey crypto.XPrvKey
	RootKey  crypto.XPrvKey
	Network  cardano.Network
}

func (w *Wallet) marshal() ([]byte, error) {
	wd := &walletDump{
		ID:       w.ID,
		Name:     w.Name,
		Keys:     w.addrKeys,
		StakeKey: w.stakeKey,
		RootKey:  w.rootKey,
		Network:  w.network,
	}
	bytes, err := json.Marshal(wd)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func (w *Wallet) unmarshal(bytes []byte) error {
	wd := &walletDump{}
	err := json.Unmarshal(bytes, wd)
	if err != nil {
		return err
	}
	w.ID = wd.ID
	w.Name = wd.Name
	w.addrKeys = wd.Keys
	w.stakeKey = wd.StakeKey
	w.rootKey = wd.RootKey
	w.network = wd.Network
	return nil
}

var newEntropy = func(bitSize int) []byte {
	entropy, _ := bip39.NewEntropy(bitSize)
	return entropy
}
