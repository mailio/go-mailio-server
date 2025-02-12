package util

import (
	"github.com/go-kit/log/level"
	diskusagehandlers "github.com/mailio/go-mailio-diskusage-handler"
	"github.com/mailio/go-mailio-server/diskusage"
	"github.com/mailio/go-mailio-server/global"
)

/**
 * GetDiskUsageFromDiskHandlers returns the total disk usage for the given address from all disk usage handlers
 * @param address the address to get the disk usage for
 **/
func GetDiskUsageFromDiskHandlers(address string) int64 {
	totalDiskUsageFromHandlers := int64(0)
	for _, diskUsageHandler := range diskusage.Handlers() {
		awsDiskUsage, awsDuErr := diskusage.GetHandler(diskUsageHandler).GetDiskUsage(address)
		if awsDuErr != nil {
			if awsDuErr != diskusagehandlers.ErrNotFound {
				level.Error(global.Logger).Log("error retrieving disk usage stats", awsDuErr.Error())
			}
		}
		if awsDiskUsage != nil {
			totalDiskUsageFromHandlers += awsDiskUsage.SizeBytes
		}
	}
	return totalDiskUsageFromHandlers
}
