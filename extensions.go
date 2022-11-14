package go_ztm

import (
	"math/rand"
	"strconv"
)

func ConvertToInt(u interface{}, ernVal int) int {

	var res int = ernVal
	switch x := u.(type) {
	case int:
		res = x
	case float64:
		res = int(x)
	case string:
		res, _ = strconv.Atoi(x)
	default:
		return ernVal
	}
	return res
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

func RandomString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
