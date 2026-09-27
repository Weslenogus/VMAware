package main

import (
	"fmt"
	"os"
	"sort"
)

// wagnerFischer mirrors wagner_fischer.cpp's wagner_fischer: plain Levenshtein
// edit distance (https://en.wikipedia.org/wiki/Wagner%E2%80%93Fischer_algorithm),
// used only to suggest a correction for an unrecognized CLI argument.
func wagnerFischer(aInput, bInput string) uint8 {
	a, b := aInput, bInput
	if len(a) > len(b) {
		a, b = b, a
	}

	aLen, bLen := len(a), len(b)

	prevRow := make([]int, aLen+1)
	currRow := make([]int, aLen+1)

	for j := 0; j <= aLen; j++ {
		prevRow[j] = j
	}

	for i := 1; i <= bLen; i++ {
		currRow[0] = i

		for j := 1; j <= aLen; j++ {
			add := prevRow[j] + 1
			del := currRow[j-1] + 1
			change := prevRow[j-1]

			if a[j-1] != b[i-1] {
				change++
			}

			currRow[j] = min3(add, del, change)
		}

		prevRow, currRow = currRow, prevRow
	}

	if prevRow[aLen] > 255 {
		return 255
	}
	return uint8(prevRow[aLen])
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

// suggest mirrors wagner_fischer.cpp's suggest: every dictionary entry within
// edit distance 2, sorted by distance.
func suggest(misspelledWord string, dictionary []argTableEntry) []string {
	type candidate struct {
		distance uint8
		word     string
	}

	var candidates []candidate
	for _, word := range dictionary {
		distance := wagnerFischer(word.Name, misspelledWord)
		if distance <= 2 {
			candidates = append(candidates, candidate{distance, word.Name})
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].distance < candidates[j].distance
	})

	suggestions := make([]string, 0, len(candidates))
	for _, c := range candidates {
		suggestions = append(suggestions, c.word)
	}
	return suggestions
}

// manageOutput mirrors wagner_fischer.cpp's manage_output.
func manageOutput(suggestions []string) {
	if len(suggestions) == 0 {
		return
	}

	fmt.Fprint(os.Stderr, "Did you mean: \"")
	for i, s := range suggestions {
		if i > 0 {
			fmt.Fprint(os.Stderr, ", ")
		}
		fmt.Fprint(os.Stderr, boldStr+s+ansiExit)
	}
	fmt.Fprint(os.Stderr, "\"?\n")
}
