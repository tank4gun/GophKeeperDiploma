package validator

import "os"

// CheckFileExistence - check that given file exists
func CheckFileExistence(path string) bool {
	if _, err := os.OpenFile(path, os.O_RDONLY, 0777); err != nil {
		return false
	}
	return true
}

// CheckStringToken - check string token
func CheckStringToken(token string, length int) bool {
	if len(token) < length {
		return false
	}
	return true
}
