//go:build windows

package artifact

import "os"

func openArtifactNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}
