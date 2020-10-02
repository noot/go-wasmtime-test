package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"runtime/pprof"
	"time"

	//"github.com/ChainSafe/gossamer/lib/keystore"
	"github.com/ChainSafe/gossamer/dot/types"
	"github.com/ChainSafe/gossamer/lib/babe"
	"github.com/ChainSafe/gossamer/lib/common"
	gssmrruntime "github.com/ChainSafe/gossamer/lib/runtime"
	"github.com/ChainSafe/gossamer/lib/scale"

	"github.com/ChainSafe/gossamer/lib/trie"
	log "github.com/ChainSafe/log15"
	"github.com/bytecodealliance/wasmtime-go"
)

var memprofile = flag.String("memprofile", "", "write memory profile to `file`")

type Ctx struct {
	storage   *testRuntimeStorage
	allocator *gssmrruntime.FreeingBumpHeapAllocator
	//keystore    *keystore.GenericKeystore
}

var ctx = &Ctx{
	storage: newTestRuntimeStorage(trie.NewEmptyTrie()),
}

var logger = log.New("pkg", "runtime")

func main() {
	flag.Parse()
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
	ext_malloc := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, size int32) int32 {
		logger.Trace("[ext_malloc] executing...")
		res, err := ctx.allocator.Allocate(uint32(size))
		if err != nil {
			logger.Error("[ext_malloc]", "Error:", err)
		}
		return int32(res)
	})
	ext_free := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, addr int32) {
		logger.Trace("[ext_free] executing...")
		err := ctx.allocator.Deallocate(uint32(addr))
		if err != nil {
			logger.Error("[ext_free]", "error", err)
		}
	})
	ext_print_utf8 := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, data, len int32) {
		logger.Trace("[ext_print_utf8] executing...")
		m := c.GetExport("memory").Memory()
		mem := m.UnsafeData()
		logger.Info("[ext_print_utf8]", "message", mem[data:data+len])
		runtime.KeepAlive(m)
	})
	ext_print_hex := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, offset, size int32) {
		logger.Trace("[ext_print_hex] executing...")
	})
	ext_get_storage_into := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, keyData, keyLen, valueData, valueLen, valueOffset int32) int32 {
		logger.Trace("[ext_get_storage_into] executing...")
		return 0
	})
	ext_set_storage := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, keyData, keyLen, valueData, valueLen int32) {
		logger.Trace("[ext_set_storage] executing...")
	})
	ext_set_child_storage := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, storageKeyData, storageKeyLen, keyData, keyLen, valueData, valueLen int32) {
		logger.Trace("[ext_set_child_storage] executing...")
	})
	ext_storage_root := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, resultPtr int32) {
		logger.Trace("[ext_storage_root] executing...")
	})
	ext_storage_changes_root := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, d int32) int32 {
		logger.Trace("[ext_storage_changes_root] executing...")
		return 0
	})
	ext_get_allocated_storage := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, keyData, keyLen, writtenOut int32) int32 {
		logger.Trace("[ext_get_allocated_storage] executing...")
		return 0
	})
	ext_clear_storage := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, keyData, keyLen int32) {
		logger.Trace("[ext_clear_storage] executing...")
	})
	ext_clear_prefix := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, prefixData, prefixLen int32) {
		logger.Trace("[ext_clear_prefix] executing...")
	})
	ext_blake2_256_enumerated_trie_root := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, valuesData, lensData, lensLen, result int32) {
		logger.Trace("[ext_blake2_256_enumerated_trie_root] executing...")
	})
	ext_blake2_256 := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, data, length, out int32) {
		logger.Trace("[ext_blake2_256] executing...")
	})
	ext_twox_64 := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, data, length, out int32) {
		logger.Trace("[ext_twox_64] executing...")
	})
	ext_twox_128 := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, data, len, out int32) {
		logger.Trace("[ext_twox_128] executing...")
		m := c.GetExport("memory").Memory()
		mem := m.UnsafeData()
		logger.Info("[ext_twox_128]", "hashing", mem[data:data+len])

		res, err := common.Twox128Hash(mem[data : data+len])
		if err != nil {
			logger.Trace("error hashing in ext_twox_128", "error", err)
		}
		copy(mem[out:out+16], res)
		runtime.KeepAlive(m)
	})
	ext_sr25519_generate := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, idData, seed, seedLen, out int32) {
		logger.Trace("[ext_sr25519_generate] executing...")
	})
	ext_sr25519_public_keys := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, idData, resultLen int32) int32 {
		logger.Trace("[ext_sr25519_public_keys] executing...")
		return 0
	})
	ext_sr25519_sign := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, idData, pubkeyData, msgData, msgLen, out int32) int32 {
		logger.Trace("[ext_sr25519_sign] executing...")
		return 0
	})
	ext_sr25519_verify := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, msgData, msgLen, sigData, pubkeyData int32) int32 {
		logger.Trace("[ext_sr25519_verify] executing...")
		return 0
	})
	ext_ed25519_generate := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, idData, seed, seedLen, out int32) {
		logger.Trace("[ext_ed25519_generate] executing...")
	})
	ext_ed25519_verify := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, msgData, msgLen, sigData, pubkeyData int32) int32 {
		logger.Trace("[ext_ed25519_verify] executing...")
		return 0
	})
	ext_is_validator := wasmtime.WrapFunc(store, func(c *wasmtime.Caller) int32 {
		logger.Trace("[ext_is_validator] executing...")
		return 0
	})
	ext_local_storage_get := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, kind, key, keyLen, valueLen int32) int32 {
		logger.Trace("[ext_local_storage_get] executing...")
		return 0
	})
	ext_local_storage_compare_and_set := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, kind, key, keyLen, oldValue, oldValueLen, newValue, newValueLen int32) int32 {
		logger.Trace("[ext_local_storage_compare_and_set] executing...")
		return 0
	})
	ext_network_state := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, writtenOut int32) int32 {
		logger.Trace("[ext_network_state] executing...")
		return 0
	})
	ext_submit_transaction := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, data, len int32) int32 {
		logger.Trace("[ext_submit_transaction] executing...")
		return 0
	})
	ext_local_storage_set := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, kind, key, keyLen, value, valueLen int32) {
		logger.Trace("[ext_local_storage_set] executing...")
	})
	ext_kill_child_storage := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b int32) {
		logger.Trace("[ext_kill_child_storage] executing...")
	})
	ext_sandbox_memory_new := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b int32) int32 {
		logger.Trace("[ext_sandbox_memory_new] executing...")
		return 0
	})
	ext_sandbox_memory_teardown := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a int32) {
		logger.Trace("[ext_sandbox_memory_teardown] executing...")
	})
	ext_sandbox_instantiate := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, g, d, e, f int32) int32 {
		logger.Trace("[ext_sandbox_instantiate] executing...")
		return 0
	})
	ext_sandbox_invoke := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, i, d, e, f, g, h int32) int32 {
		logger.Trace("[ext_sandbox_invoke] executing...")
		return 0
	})
	ext_sandbox_instance_teardown := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a int32) {
		logger.Trace("[ext_sandbox_instance_teardown] executing...")
	})
	ext_get_allocated_child_storage := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, i, d, e int32) int32 {
		logger.Trace("[ext_get_allocated_child_storage] executing...")
		return 0
	})
	ext_child_storage_root := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, i int32) int32 {
		logger.Trace("[ext_child_storage_root] executing...")
		return 0
	})
	ext_clear_child_storage := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, d, z int32) {
		logger.Trace("[ext_clear_child_storage] executing...")
	})
	ext_secp256k1_ecdsa_recover_compressed := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, i int32) int32 {
		logger.Trace("[ext_secp256k1_ecdsa_recover_compressed] executing...")
		return 0
	})
	ext_sandbox_memory_get := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, d, z int32) int32 {
		logger.Trace("[ext_sandbox_memory_get] executing...")
		return 0
	})
	ext_sandbox_memory_set := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, d, z int32) int32 {
		logger.Trace("[ext_sandbox_memory_set] executing...")
		return 0
	})
	ext_log := wasmtime.WrapFunc(store, func(c *wasmtime.Caller, a, b, d, e, z int32) {
		logger.Trace("[ext_log] executing...")
	})

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
		ext_blake2_256.AsExtern(),
		ext_twox_128.AsExtern(),
		ext_clear_storage.AsExtern(),
		ext_set_storage.AsExtern(),
		ext_get_allocated_storage.AsExtern(),
		ext_get_storage_into.AsExtern(),
		ext_kill_child_storage.AsExtern(),
		ext_sandbox_memory_new.AsExtern(),
		ext_sandbox_memory_teardown.AsExtern(),
		ext_sandbox_instantiate.AsExtern(),
		ext_sandbox_invoke.AsExtern(),
		ext_sandbox_instance_teardown.AsExtern(),
		ext_print_utf8.AsExtern(),
		ext_print_hex.AsExtern(),
		ext_print_num.AsExtern(),
		ext_is_validator.AsExtern(),
		ext_local_storage_get.AsExtern(),
		ext_local_storage_compare_and_set.AsExtern(),
		ext_sr25519_public_keys.AsExtern(),
		ext_network_state.AsExtern(),
		ext_sr25519_sign.AsExtern(),
		ext_submit_transaction.AsExtern(),
		ext_local_storage_set.AsExtern(),
		ext_get_allocated_child_storage.AsExtern(),
		ext_ed25519_generate.AsExtern(),
		ext_sr25519_generate.AsExtern(),
		ext_child_storage_root.AsExtern(),
		ext_clear_prefix.AsExtern(),
		ext_storage_root.AsExtern(),
		ext_storage_changes_root.AsExtern(),
		ext_clear_child_storage.AsExtern(),
		ext_set_child_storage.AsExtern(),
		ext_secp256k1_ecdsa_recover_compressed.AsExtern(),
		ext_ed25519_verify.AsExtern(),
		ext_sr25519_verify.AsExtern(),
		ext_sandbox_memory_get.AsExtern(),
		ext_sandbox_memory_set.AsExtern(),
		ext_blake2_256_enumerated_trie_root.AsExtern(),
		ext_malloc.AsExtern(),
		ext_free.AsExtern(),
		ext_twox_64.AsExtern(),
		ext_log.AsExtern(),
	})
	check(err)

	mem := instance.GetExport("memory").Memory()
	data := mem.UnsafeData()
	ctx.allocator = gssmrruntime.NewAllocator(data, 0)

	// mem := instance.GetExport("memory").Memory()
	// data := mem.UnsafeData()

	// run := instance.GetExport("Core_version").Func()
	// resi, err := run.Call(1, 0)
	// check(err)

	// ret := resi.(int64)

	// length := int32(ret >> 32)
	// offset := int32(ret)

	// version := &gssmrruntime.VersionAPI{
	// 	RuntimeVersion: &gssmrruntime.Version{},
	// 	API:            nil,
	// }

	// version.Decode(data[offset : offset+length])
	// fmt.Printf("Spec_name: %s\n", version.RuntimeVersion.Spec_name)
	// fmt.Printf("Impl_name: %s\n", version.RuntimeVersion.Impl_name)
	// fmt.Printf("Authoring_version: %d\n", version.RuntimeVersion.Authoring_version)
	// fmt.Printf("Spec_version: %d\n", version.RuntimeVersion.Spec_version)
	// fmt.Printf("Impl_version: %d\n", version.RuntimeVersion.Impl_version)
	//runtime.KeepAlive(mem)
	err = babe_configuration(instance)
	check(err)

	// err = initialize_block(instance)
	// check(err)

	// apply_inherent_extrinsics(instance)
	// check(err)

	// finalize_block(instance)
	// check(err)

	if *memprofile != "" {
		fmt.Println("creating memprofile")
		f, err := os.Create(*memprofile)
		if err != nil {
			fmt.Printf("could not create memory profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		runtime.GC()    // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			fmt.Printf("could not write memory profile: ", err)
		}
	}
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func exec(instance *wasmtime.Instance, function string, data []byte) ([]byte, error) {
	ptr, err := ctx.allocator.Allocate(uint32(len(data)))
	if err != nil {
		return nil, err
	}

	defer func() {
		err = ctx.allocator.Deallocate(ptr)
		if err != nil {
			logger.Error("exec: could not free ptr", "error", err)
		}
	}()

	mem := instance.GetExport("memory").Memory()
	memdata := mem.UnsafeData()
	copy(memdata[ptr:ptr+uint32(len(data))], data)

	run := instance.GetExport(function).Func()
	resi, err := run.Call(int32(ptr), int32(len(data)))
	if err != nil {
		return nil, err
	}

	if resi == nil {
		return []byte{}, err
	}

	ret := resi.(int64)
	length := int32(ret >> 32)
	offset := int32(ret)
	return memdata[offset : offset+length], nil
}

func babe_configuration(instance *wasmtime.Instance) error {
	ret, err := exec(instance, "BabeApi_configuration", []byte{})
	if err != nil {
		return err
	}

	cfg, err := scale.Decode(ret, new(types.BabeConfiguration))
	if err != nil {
		return err
	}

	fmt.Println(cfg)
	return nil
}

func initialize_block(instance *wasmtime.Instance) error {
	header := &types.Header{
		ParentHash: trie.EmptyHash,
		Number:     big.NewInt(77),
		//StateRoot: trie.EmptyHash,
		//ExtrinsicsRoot: trie.EmptyHash,
		Digest: [][]byte{},
	}

	encodedHeader, err := scale.Encode(header)
	if err != nil {
		return fmt.Errorf("cannot encode header: %s", err)
	}

	encodedHeader = append(encodedHeader, 0)

	ret, err := exec(instance, "Core_initialize_block", encodedHeader)
	if err != nil {
		return err
	}
	fmt.Println(ret)
	return nil
}

func apply_inherent_extrinsics(instance *wasmtime.Instance) error {
	idata := babe.NewInherentsData()
	err := idata.SetInt64Inherent(babe.Timstap0, uint64(time.Now().Unix()))
	if err != nil {
		return err
	}

	// add babeslot
	err = idata.SetInt64Inherent(babe.Babeslot, 1)
	if err != nil {
		return err
	}

	// add finalnum
	err = idata.SetBigIntInherent(babe.Finalnum, big.NewInt(0))
	if err != nil {
		return err
	}

	ienc, err := idata.Encode()
	if err != nil {
		return err
	}

	// Call BlockBuilder_inherent_extrinsics which returns the inherents as extrinsics
	inherentExts, err := exec(instance, "BlockBuilder_inherent_extrinsics", ienc)
	if err != nil {
		return err
	}

	// decode inherent extrinsics
	exts, err := scale.Decode(inherentExts, [][]byte{})
	if err != nil {
		return err
	}

	// apply each inherent extrinsic
	for _, ext := range exts.([][]byte) {
		in, err := scale.Encode(ext)
		if err != nil {
			return err
		}

		ret, err := exec(instance, "BlockBuilder_apply_extrinsic", in)
		if err != nil {
			return err
		}

		if !bytes.Equal(ret, []byte{0, 0}) {
			return fmt.Errorf("error applying extrinsic: %v", ret)
		}
	}

	return nil
}

func finalize_block(instance *wasmtime.Instance) (*types.Header, error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("recovered", r)
		}
	}()

	ret, err := exec(instance, "BlockBuilder_finalize_block", []byte{})
	if err != nil {
		return nil, err
	}

	bh := new(types.Header)
	// _, err = scale.Decode(ret, bh)
	// if err != nil {
	// 	return nil, err
	// }

	fmt.Println(ret)

	return bh, nil
}

func core_version(instance *wasmtime.Instance) {
	mem := instance.GetExport("memory").Memory()
	data := mem.UnsafeData()

	run := instance.GetExport("Core_version").Func()
	resi, err := run.Call(1, 0)
	check(err)

	ret := resi.(int64)

	length := int32(ret >> 32)
	offset := int32(ret)

	version := &gssmrruntime.VersionAPI{
		RuntimeVersion: &gssmrruntime.Version{},
		API:            nil,
	}

	version.Decode(data[offset : offset+length])
	fmt.Printf("Spec_name: %s\n", version.RuntimeVersion.Spec_name)
	fmt.Printf("Impl_name: %s\n", version.RuntimeVersion.Impl_name)
	fmt.Printf("Authoring_version: %d\n", version.RuntimeVersion.Authoring_version)
	fmt.Printf("Spec_version: %d\n", version.RuntimeVersion.Spec_version)
	fmt.Printf("Impl_version: %d\n", version.RuntimeVersion.Impl_version)
	runtime.KeepAlive(mem)
}
