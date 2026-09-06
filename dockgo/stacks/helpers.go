package stacks

// Contains reports whether values contains target.
func Contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// FirstOrEmpty returns the first value or an empty string.
func FirstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
