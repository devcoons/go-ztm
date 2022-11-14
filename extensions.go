package go_ztm

import "strconv"

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
