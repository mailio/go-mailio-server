package util

import "net"

func CheckMXRecords(domain string) (bool, error) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return false, err
	}
	if len(mxRecords) > 0 {
		return true, nil
	}
	return false, nil
}
