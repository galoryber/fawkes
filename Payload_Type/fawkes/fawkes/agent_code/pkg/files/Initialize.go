package files

import (
	"log"
	"sync"
)

const FILE_CHUNK_SIZE = 512000 // Normal Mythic chunk size (512KB)

var initOnce sync.Once

func Initialize() {
	initOnce.Do(func() {
		// Start listening for sending a file to Mythic ("download")
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[ERROR] File send goroutine panic: %v", r)
				}
			}()
			listenForSendFileToMythicMessages()
		}()
		// Start listening for getting a file from Mythic ("upload")
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[ERROR] File get goroutine panic: %v", r)
				}
			}()
			listenForGetFromMythicMessages()
		}()
	})
}
