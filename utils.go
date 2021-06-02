package fibercasbin

func containsString(s []string, v string) bool {
	for _, vv := range s {
		if vv == v {
			return true
		}
	}
	return false
}

func stringSliceToInterfaceSlice(arr []string) []interface{} {
	in := make([]interface{}, len(arr))
	for i, a := range arr {
		in[i] = a
	}
	return in
}
