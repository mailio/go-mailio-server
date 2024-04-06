package util

import "github.com/mailio/go-mailio-server/types"

// count the number of messages in all folders except sent
func SumUpItemsFromFolderCountResponse(folders []string, response *types.CouchDBCountDistinctFromResponse) int {
	total := 0
	// folder to map (for simpler lookup)
	folderMap := make(map[string]bool)
	for _, folder := range folders {
		folderMap[folder] = true
	}
	for _, row := range response.Rows {
		for _, b := range row.Key {
			if _, ok := folderMap[b]; !ok {
				total += row.Value
			}
		}
	}
	return total
}
