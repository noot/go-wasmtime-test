package main

import (
	"encoding/binary"
	"github.com/ChainSafe/gossamer/lib/common"
	"github.com/ChainSafe/gossamer/lib/trie"
)

type testRuntimeStorage struct {
	trie *trie.Trie
}

func newTestRuntimeStorage(tr *trie.Trie) *testRuntimeStorage {
	if tr == nil {
		tr = trie.NewEmptyTrie()
	}
	return &testRuntimeStorage{
		trie: tr,
	}
}

func (trs testRuntimeStorage) TrieAsString() string {
	return trs.trie.String()
}

func (trs testRuntimeStorage) Set(key []byte, value []byte) error {
	return trs.trie.Put(key, value)
}

func (trs testRuntimeStorage) Get(key []byte) ([]byte, error) {
	return trs.trie.Get(key)
}

func (trs testRuntimeStorage) Root() (common.Hash, error) {
	return trs.trie.Hash()
}

func (trs testRuntimeStorage) SetChild(keyToChild []byte, child *trie.Trie) error {
	return trs.trie.PutChild(keyToChild, child)
}

func (trs testRuntimeStorage) SetChildStorage(keyToChild, key, value []byte) error {
	return trs.trie.PutIntoChild(keyToChild, key, value)
}

func (trs testRuntimeStorage) GetChildStorage(keyToChild, key []byte) ([]byte, error) {
	return trs.trie.GetFromChild(keyToChild, key)
}

func (trs testRuntimeStorage) Delete(key []byte) error {
	return trs.trie.Delete(key)
}

func (trs testRuntimeStorage) Entries() map[string][]byte {
	return trs.trie.Entries()
}

func (trs testRuntimeStorage) SetBalance(key [32]byte, balance uint64) error {
	skey, err := common.BalanceKey(key)
	if err != nil {
		return err
	}

	bb := make([]byte, 8)
	binary.LittleEndian.PutUint64(bb, balance)

	return trs.Set(skey, bb)
}

func (trs testRuntimeStorage) GetBalance(key [32]byte) (uint64, error) {
	skey, err := common.BalanceKey(key)
	if err != nil {
		return 0, err
	}

	bal, err := trs.Get(skey)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint64(bal), nil
}
