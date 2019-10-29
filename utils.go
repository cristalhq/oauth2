package oauth2

import (
	"net/url"
)

func cloneURLValues(vals url.Values) url.Values {
	if vals == nil {
		return url.Values{}
	}

	v2 := make(url.Values, len(vals))
	for k, v := range vals {
		v2[k] = append([]string(nil), v...)
	}
	return v2
}
