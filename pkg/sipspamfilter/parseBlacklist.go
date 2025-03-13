package sipspamfilter

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (cfg *spamFilter) parseNumberLists() error {
	cfg.parserLock.Lock()
	defer cfg.parserLock.Unlock()

	newBlacklist, err := cfg.parseNumberList(cfg.config.Spam.BlacklistPaths)
	if err != nil {
		return err
	}

	newWhitelist, err := cfg.parseNumberList(cfg.config.Spam.WhitelistPaths)
	if err != nil {
		return err
	}

	cfg.blacklistLock.Lock()
	cfg.whitelistLock.Lock()
	defer cfg.blacklistLock.Unlock()
	defer cfg.whitelistLock.Unlock()
	cfg.blacklistNumbers = newBlacklist
	cfg.whitelistNumbers = newWhitelist

	return nil
}

func (cfg *spamFilter) parseNumberList(paths []string) (newList []*numberList, err error) {
	for _, path := range paths {
		fileInfo, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("could not access path %s: %v", path, err)
		}

		if fileInfo.IsDir() {
			// Handle directory
			err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() {
					bl, err := cfg.parseFile(filePath)
					if err != nil {
						return fmt.Errorf("error parsing file %s: %v", filePath, err)
					}
					newList = append(newList, bl)
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("error walking directory %s: %v", path, err)
			}
		} else {
			// Handle single file
			bl, err := cfg.parseFile(path)
			if err != nil {
				return nil, fmt.Errorf("error parsing file %s: %v", path, err)
			}
			newList = append(newList, bl)
		}
	}

	return newList, nil
}

// Helper function to parse individual files
func (cfg *spamFilter) parseFile(filePath string) (*numberList, error) {
	log := cfg.log.WithPrefix(fmt.Sprintf("parseFile: %s: ", filePath))
	newList := &numberList{
		fileName: filePath,
		numbers:  make(map[string]number),
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Strip comments from the line
		lineSplit := strings.Split(line, "#")
		line = strings.TrimRight(strings.TrimSpace(lineSplit[0]), "\n\r")
		if line == "" {
			continue
		}
		comment := ""
		if len(lineSplit) > 1 {
			comment = strings.TrimRight(strings.TrimSpace(lineSplit[1]), "\n\r")
		}

		// Check if number starts with +
		if !strings.HasPrefix(line, "+") {
			log.Warn("Number in file %s line %d does not start with +: %s", filePath, lineNo, line)
		}

		if val, ok := newList.numbers[line]; ok {
			log.Warn("Ignoring duplicate number on line number %d (first seen on line %d) in file %s", lineNo, val.lineNumber, filePath)
		} else {
			newList.numbers[line] = number{
				lineNumber: lineNo,
				comment:    comment,
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return newList, nil
}
