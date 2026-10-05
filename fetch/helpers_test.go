package fetch

import "os"

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
