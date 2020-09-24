package main

import (
	"fmt"
	//"runtime"

	//"github.com/ChainSafe/gossamer/lib/keystore"
	"github.com/ChainSafe/gossamer/lib/runtime"
	"github.com/ChainSafe/gossamer/lib/trie"
	log "github.com/ChainSafe/log15"
	"github.com/bytecodealliance/wasmtime-go"
)

// var ctx = struct {
// 	tr  *trie.Trie
// 	mem []byte
// }{
// 	tr:  trie.NewEmptyTrie(),
// 	mem: []byte("hello"),
// }

type Ctx struct {
	storage   *testRuntimeStorage
	allocator *runtime.FreeingBumpHeapAllocator
	//keystore    *keystore.GenericKeystore
}

var ctx = &Ctx{
	storage: newTestRuntimeStorage(trie.NewEmptyTrie()),
}

var logger = log.New("pkg", "runtime")

func main() {
	// Almost all operations in wasmtime require a contextual `store`
	// argument to share, so create that first
	//store := wasmtime.NewStore(wasmtime.NewEngine())
	engine := wasmtime.NewEngine()
	store := wasmtime.NewStore(engine)

	// Compiling modules requires WebAssembly binary input, but the wasmtime
	// package also supports converting the WebAssembly text format to the
	// binary format.
	// wasm, err := wasmtime.Wat2Wasm(`
	//      (module
	//  		(type $t0 (func (param i32 i32)))
	//        (import "env" "ext_log" (func $ext_log (type $t0)))
	// 	  (func $test_ext_log (export "test_ext_log") (type $t0) (param $p0 i32) (param $p1 i32)
	// 	    (call $ext_log
	// 	      (local.get $p0)
	// 	      (local.get $p1)))
	// 	   (memory $memory (export "memory") 16)
	//      )
	//    `)
	// check(err)

	// Once we have our binary `wasm` we can compile that into a `*Module`
	// which represents compiled JIT code.
	//module, err := wasmtime.NewModule(engine, wasm)
	module, err := wasmtime.NewModuleFromFile(engine, "node_runtime.compact.wasm")
	check(err)

	ext_print_num := wasmtime.WrapFunc(store, func(data int64) {
		logger.Trace("[ext_print_num] executing...")
		logger.Debug("[ext_print_num]", "message", fmt.Sprintf("%d", data))
	})
	ext_malloc := wasmtime.WrapFunc(store, func(size int32) int32 {
		return 0
	})
	ext_print_utf8 := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, data, len int32) {})
	ext_print_hex := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, offset, size int32) {})
	ext_get_storage_into := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, keyData, keyLen, valueData, valueLen, valueOffset int32) int32 {
		return 0
	})
	ext_set_storage := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, keyData, keyLen, valueData, valueLen int32) {})
	ext_set_child_storage := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, storageKeyLen, keyData, keyLen, valueData, valueLen int32) {})
	ext_storage_root := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, resultPtr int32) {})
	ext_storage_changes_root := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, d int32) {})
	ext_get_allocated_storage := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, keyData, keyLen, writtenOut int32) int32 {
		return 0
	})
	ext_clear_storage := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, keyData, keyLen int32) {})
	ext_clear_prefix := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, prefixData, prefixLen int32) {})
	ext_blake2_256_enumerated_trie_root := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, valuesData, lensData, lensLen, result int32) {})
	ext_blake2_256 := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, data, length, out int32) {})
	ext_twox_64 := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, data, length, out int32) {})
	ext_twox_128 := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, data, length, out int32) {})
	ext_sr25519_generate := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, idData, seed, seedLen, out int32) {})
	ext_sr25519_public_keys := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, idData, resultLen int32) int32 {
		return 0
	})
	ext_sr25519_sign := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, idData, pubkeyData, msgData, msgLen, out int32) int32 {
		return 0
	})
	ext_sr25519_verify := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, msgData, msgLen, sigData, pubkeyData int32) int32 {
		return 0
	})
	ext_ed25519_generate := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, idData, seed, seedLen, out int32) {})
	ext_ed25519_verify := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, msgData, msgLen, sigData, pubkeyData int32) int32 {
		return 0
	})
	ext_secp256k1_ecdsa_recover := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, msgData, sigData, pubkeyData int32) int32 {
		return 0
	})
	ext_is_validator := wasmtime.WrapFunc(store, func(c *wasmtime.Caller) int32 {
		return 0
	})
	ext_local_storage_get := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, kind, key, keyLen, valueLen int32) int32 {
		return 0
	})
	ext_local_storage_compare_and_set := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, kind, key, keyLen, oldValue, oldValueLen, newValue, newValueLen int32) int32 {
		return 0
	})
	ext_network_state := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, writtenOut int32) int32 {
		return 0
	})
	ext_submit_transaction := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, data, len int32) int32 {
		return 0
	})
	ext_local_storage_set := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, kind, key, keyLen, value, valueLen int32) {})
	ext_kill_child_storage := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b int32) {})
	ext_sandbox_memory_new := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b int32) int32 {
		return 0
	})
	ext_sandbox_memory_teardown := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a int32) {})
	ext_sandbox_instantiate := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, g, d, e, f int32) int32 {
		return 0
	})
	ext_sandbox_invoke := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, i, d, e, f, g, h int32) int32 {
		return 0
	})
	ext_sandbox_instance_teardown := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a int32) {})
	ext_get_allocated_child_storage := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, i, d, e int32) int32 {
		return 0
	})
	ext_child_storage_root := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, i int32) int32 {
		return 0
	})
	ext_clear_child_storage := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, d, z int32) {})
	ext_secp256k1_ecdsa_recover_compressed := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, i int32) int32 {
		return 0
	})
	ext_sandbox_memory_get := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, d, z int32) int32 {
		return 0
	})
	ext_sandbox_memory_set := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, d, z int32) int32 {
		return 0
	})
	ext_log := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, d, e, z int32) {})

	// item := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b int32) {
	// 	m := c.GetExport("memory").Memory()
	// 	runtime.KeepAlive(m)
	// 	mem := m.UnsafeData()
	// 	//msg := ctx.Global().Get().Externref()
	// 	//ctx.tr.Put([]byte("key"), []byte("value"))
	// 	fmt.Println(string(mem[a:b]))
	// 	copy(mem[a:b], []byte("helloworld"))
	// 	//fmt.Println("Hello from Go!")
	// })

	// Next up we instantiate a module which is where we link in all our
	// imports. We've got one import so we pass that in here.
	instance, err := wasmtime.NewInstance(store, module, []*wasmtime.Extern{
		ext_print_num.AsExtern(),
		ext_malloc.AsExtern(),
		ext_print_utf8.AsExtern(),
		ext_print_hex.AsExtern(),
		ext_get_storage_into.AsExtern(),
		ext_set_storage.AsExtern(),
		ext_set_child_storage.AsExtern(),
		ext_storage_root.AsExtern(),
		ext_storage_changes_root.AsExtern(),
		ext_get_allocated_storage.AsExtern(),
		ext_clear_storage.AsExtern(),
		ext_clear_prefix.AsExtern(),
		ext_blake2_256_enumerated_trie_root.AsExtern(),
		ext_blake2_256.AsExtern(),
		ext_twox_64.AsExtern(),
		ext_twox_128.AsExtern(),
		ext_sr25519_generate.AsExtern(),
		ext_sr25519_public_keys.AsExtern(),
		ext_sr25519_sign.AsExtern(),
		ext_sr25519_verify.AsExtern(),
		ext_ed25519_generate.AsExtern(),
		ext_ed25519_verify.AsExtern(),
		ext_secp256k1_ecdsa_recover.AsExtern(),
		ext_is_validator.AsExtern(),
		ext_local_storage_get.AsExtern(),
		ext_local_storage_compare_and_set.AsExtern(),
		ext_network_state.AsExtern(),
		ext_submit_transaction.AsExtern(),
		ext_local_storage_set.AsExtern(),
		ext_kill_child_storage.AsExtern(),
		ext_sandbox_memory_new.AsExtern(),
		ext_sandbox_memory_teardown.AsExtern(),
		ext_sandbox_instantiate.AsExtern(),
		ext_sandbox_invoke.AsExtern(),
		ext_sandbox_instance_teardown.AsExtern(),
		ext_get_allocated_child_storage.AsExtern(),
		ext_child_storage_root.AsExtern(),
		ext_clear_child_storage.AsExtern(),
		ext_secp256k1_ecdsa_recover_compressed.AsExtern(),
		ext_sandbox_memory_get.AsExtern(),
		ext_sandbox_memory_set.AsExtern(),
		ext_log.AsExtern(),
	})
	check(err)

	// After we've instantiated we can lookup our `run` function and call
	// it.
	run := instance.GetExport("test_ext_log").Func()
	_, err = run.Call(0, 10)
	check(err)

	_, err = run.Call(0, 10)
	check(err)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
