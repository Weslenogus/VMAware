//go:build js && wasm

// Command browser builds the browser-facing WASM binding for VMAware's
// scoring engine.
//
// A browser sandbox has no CPUID, filesystem, or registry access, so the
// real OS-probing technique functions in pkg/vmaware can't run here (they
// were verified end-to-end on real hardware for the native build — see
// pkg/vmaware/techniques_common.go — but every one of them is meaningless
// inside this WASM target). What genuinely is portable, and what this
// binding exposes, is the pure part of the engine: given a set of technique
// results gathered some other way (a signal from the host page, a server
// round-trip, or the caller's own heuristics), VMAware's exact brand-merge
// rules, threshold math, and conclusion wording (pkg/vmaware/external.go's
// EvaluateExternal) are applied faithfully, unchanged from the native
// build. This is deliberately narrower than "detect VMs in the browser",
// which is not something WASM can do.
package main

import (
	"syscall/js"

	vm "github.com/weslenogus/vmaware/go/pkg/vmaware"
)

func jsError(msg string) js.Value {
	obj := js.Global().Get("Object").New()
	obj.Set("error", msg)
	return obj
}

// jsEvaluate implements vmaware.evaluate(results, options).
//
// results: Array<{points: number, brand?: number, extraBrand?: number}>
// options: {highThreshold?: bool, dynamic?: bool, multiple?: bool}
//
// Returns {isVM, percentage, type, brand, conclusion, brandList: [{brand, brandName, score}, ...]}
func jsEvaluate(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsError("evaluate(results, options?) requires at least one argument")
	}

	resultsArg := args[0]
	if resultsArg.Type() != js.TypeObject {
		return jsError("results must be an array")
	}
	length := resultsArg.Length()

	results := make([]vm.ExternalResult, 0, length)
	for i := 0; i < length; i++ {
		item := resultsArg.Index(i)

		points := item.Get("points")
		if points.IsUndefined() || points.IsNull() {
			return jsError("each result requires a numeric 'points' field")
		}

		r := vm.ExternalResult{
			Points:     uint8(points.Int()),
			Brand:      vm.BrandNullBrand,
			ExtraBrand: vm.BrandNullBrand,
		}

		if b := item.Get("brand"); !b.IsUndefined() && !b.IsNull() {
			r.Brand = vm.BrandEnum(b.Int())
		}
		if b := item.Get("extraBrand"); !b.IsUndefined() && !b.IsNull() {
			r.ExtraBrand = vm.BrandEnum(b.Int())
		}

		results = append(results, r)
	}

	var opts vm.EvalOptions
	if len(args) > 1 && args[1].Type() == js.TypeObject {
		o := args[1]
		opts.HighThreshold = o.Get("highThreshold").Truthy()
		opts.Dynamic = o.Get("dynamic").Truthy()
		opts.Multiple = o.Get("multiple").Truthy()
	}

	result := vm.EvaluateExternal(results, opts)

	out := js.Global().Get("Object").New()
	out.Set("isVM", result.IsVM)
	out.Set("percentage", result.Percentage)
	out.Set("type", result.Type)
	out.Set("brand", result.Brand)
	out.Set("conclusion", result.Conclusion)

	brandList := js.Global().Get("Array").New(len(result.BrandList))
	for i, e := range result.BrandList {
		entry := js.Global().Get("Object").New()
		entry.Set("brand", int(e.Brand))
		entry.Set("brandName", vm.BrandEnumToString(e.Brand))
		entry.Set("score", e.Score)
		brandList.SetIndex(i, entry)
	}
	out.Set("brandList", brandList)

	return out
}

func jsFlagToString(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsError("flagToString(index) requires an argument")
	}
	return vm.FlagToString(vm.EnumFlag(args[0].Int()))
}

func jsBrandToString(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsError("brandToString(index) requires an argument")
	}
	return vm.BrandEnumToString(vm.BrandEnum(args[0].Int()))
}

func jsTypeForBrand(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsError("typeForBrand(index) requires an argument")
	}
	return vm.TypeForBrand(vm.BrandEnum(args[0].Int()))
}

func main() {
	api := js.Global().Get("Object").New()
	api.Set("evaluate", js.FuncOf(jsEvaluate))
	api.Set("flagToString", js.FuncOf(jsFlagToString))
	api.Set("brandToString", js.FuncOf(jsBrandToString))
	api.Set("typeForBrand", js.FuncOf(jsTypeForBrand))
	api.Set("brandNullBrand", int(vm.BrandNullBrand))
	api.Set("brandCount", int(vm.MaxBrands))

	js.Global().Set("vmaware", api)

	// Keep the Go runtime alive so the JS callbacks registered above stay
	// callable; the WASM instance would otherwise halt as soon as main()
	// returns.
	select {}
}
