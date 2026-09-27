package vmaware

import "sync"

// flagsMemo mirrors the small "cache keyed by the exact flagset used"
// pattern the C++ memo:: sub-namespaces use for brand()/type()/conclusion()
// (memo::single_brand, memo::multi_brand, memo::brand_list, memo::conclusion).
// It's a generic instead of one hand-copied struct per cached type, which is
// the modern-Go equivalent of the same idea, not a behavior change.
type flagsMemo[T any] struct {
	mu    sync.Mutex
	valid bool
	flags FlagSet
	value T
}

func (m *flagsMemo[T]) fetch(flags FlagSet) (T, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.valid && m.flags == flags {
		return m.value, true
	}
	var zero T
	return zero, false
}

func (m *flagsMemo[T]) store(flags FlagSet, value T) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.valid = true
	m.flags = flags
	m.value = value
}

var (
	brandListMemo   flagsMemo[[]BrandElement]
	multiBrandMemo  flagsMemo[string]
	singleBrandMemo flagsMemo[BrandEnum]
	conclusionMemo  flagsMemo[string]
)

// techniqueCacheEntry mirrors VM::memo::cache_entry / data_t.
type techniqueCacheEntry struct {
	result bool
	points uint8
	brand  BrandEnum
}

// techniqueCache mirrors VM::memo::cache_table: a memoized result per
// technique ID, covering both the built-in technique table (indices
// 0..NumFlags) and custom techniques registered through AddCustom (whose
// IDs start at BaseTechniqueCount+1). A map keyed by ID is the direct
// equivalent of the C++ fixed array plus the separate custom_table lookup,
// unified into one lookup.
var techniqueCache = struct {
	mu sync.Mutex
	m  map[uint16]techniqueCacheEntry
}{m: make(map[uint16]techniqueCacheEntry)}

func cacheIsCached(id uint16) bool {
	techniqueCache.mu.Lock()
	defer techniqueCache.mu.Unlock()
	_, ok := techniqueCache.m[id]
	return ok
}

func cacheFetch(id uint16) techniqueCacheEntry {
	techniqueCache.mu.Lock()
	defer techniqueCache.mu.Unlock()
	return techniqueCache.m[id]
}

func cacheStore(id uint16, result bool, points uint8, brand BrandEnum) {
	techniqueCache.mu.Lock()
	defer techniqueCache.mu.Unlock()
	techniqueCache.m[id] = techniqueCacheEntry{result: result, points: points, brand: brand}
}

// resetMemoCaches clears every memoized value. Mirrors what re-running
// core::run_all repeatedly would require if the cache were ever invalidated;
// exposed for callers (and tests) that want a clean slate, e.g. after
// AddCustom or Disable changes what a given flagset would compute.
func resetMemoCaches() {
	techniqueCache.mu.Lock()
	techniqueCache.m = make(map[uint16]techniqueCacheEntry)
	techniqueCache.mu.Unlock()

	brandListMemo = flagsMemo[[]BrandElement]{}
	multiBrandMemo = flagsMemo[string]{}
	singleBrandMemo = flagsMemo[BrandEnum]{}
	conclusionMemo = flagsMemo[string]{}
}
