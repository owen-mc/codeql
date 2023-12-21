package main

import "strings"

func containsBad(searchName string, names string) bool {
	values := strings.Split(names, ",")
	// BAD: index could be equal to length
	for i := 0; i <= len(values); i++ {
		// When i = length, this access will be out of bounds
		if values[i] == searchName {
			return true
		}
	}
	return false
}

func switchSanitizer(args []string) string {
	if len(args) < 2 {
		return ""
	}
	var x string
	switch len(args) {
	case 4:
		x = args[3]
	case 3:
		// GOOD, but the query treats it as bad (FP)
		x = args[2]

	}
	return x
}
