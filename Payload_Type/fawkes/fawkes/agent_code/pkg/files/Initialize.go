package files

import "sync"

const FILE_CHUNK_SIZE = 512000 // Normal Mythic chunk size (512KB)

var initOnce sync.Once

func Initialize() {
	initOnce.Do(func() {
		// Start listening for sending a file to Mythic ("download")
		go listenForSendFileToMythicMessages()
		// Start listening for getting a file from Mythic ("upload")
		go listenForGetFromMythicMessages()
	})
}
