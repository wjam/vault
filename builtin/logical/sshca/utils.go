package sshca

import "fmt"

func convertMapToStringValue(initial map[string]interface{}) map[string]string {
	result := map[string]string{}
	for key, value := range initial {
		result[key] = fmt.Sprintf("%v", value)
	}
	return result
}

func contains(array []string, needed string) bool {
	for _, item := range array {
		if item == needed {
			return true
		}
	}
	return false
}
