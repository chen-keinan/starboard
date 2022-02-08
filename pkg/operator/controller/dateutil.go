package controller

import "time"

func intervalExceeded(reportTTL time.Duration, creationTime time.Time) (bool, time.Duration, error) {
	expiresAt := creationTime.Add(reportTTL)
	currentTime := time.Now()
	isExpired := currentTime.After(expiresAt)

	if isExpired {
		return true, time.Duration(0), nil
	}

	expiresIn := expiresAt.Sub(currentTime)
	return false, expiresIn, nil
}
