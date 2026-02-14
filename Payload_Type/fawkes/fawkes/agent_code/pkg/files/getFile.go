package files

import (
	"encoding/base64"
	"encoding/json"
	"fawkes/pkg/structs"
	"fmt"
)

var GetFromMythicChannel = make(chan structs.GetFileFromMythicStruct, 10)

// listenForGetFromMythicMessages reads from GetFromMythicChannel to get a file from Mythic to the agent
func listenForGetFromMythicMessages() {
	for getFile := range GetFromMythicChannel {
		getFile.TrackingUUID = generateUUID()
		getFile.FileTransferResponse = make(chan json.RawMessage)
		getFile.Task.Job.SetFileTransfer(getFile.TrackingUUID, getFile.FileTransferResponse)
		go sendUploadFileMessagesToMythic(getFile)
	}
}

// sendUploadFileMessagesToMythic sends messages to Mythic to transfer a file from Mythic to Agent
func sendUploadFileMessagesToMythic(getFileFromMythic structs.GetFileFromMythicStruct) {
	// Request the first chunk
	fileUploadData := structs.FileUploadMessage{}
	fileUploadData.FileID = getFileFromMythic.FileID
	fileUploadData.ChunkSize = 512000
	fileUploadData.ChunkNum = 1
	fileUploadData.FullPath = getFileFromMythic.FullPath

	fileUploadMsg := structs.Response{}
	fileUploadMsg.TaskID = getFileFromMythic.Task.ID
	fileUploadMsg.Upload = &fileUploadData

	// Send the request via the SendResponses channel
	getFileFromMythic.Task.Job.SendResponses <- fileUploadMsg

	// Wait for the response
	rawData := <-getFileFromMythic.FileTransferResponse

	fileUploadMsgResponse := structs.FileUploadMessageResponse{}
	err := json.Unmarshal(rawData, &fileUploadMsgResponse)
	if err != nil {
		errResponse := structs.Response{}
		errResponse.Completed = true
		errResponse.TaskID = getFileFromMythic.Task.ID
		errResponse.UserOutput = fmt.Sprintf("Failed to parse message response from Mythic: %s", err.Error())
		getFileFromMythic.Task.Job.SendResponses <- errResponse
		getFileFromMythic.ReceivedChunkChannel <- make([]byte, 0)
		return
	}

	// Inform the user that we started getting data
	if getFileFromMythic.SendUserStatusUpdates {
		response := structs.Response{}
		response.Completed = false
		response.TaskID = getFileFromMythic.Task.ID
		response.UserOutput = fmt.Sprintf("Fetching file from Mythic with %d total chunks at %d bytes per chunk\n", fileUploadMsgResponse.TotalChunks, fileUploadData.ChunkSize)
		getFileFromMythic.Task.Job.SendResponses <- response
	}

	// Decode and send the first chunk
	decoded, err := base64.StdEncoding.DecodeString(fileUploadMsgResponse.ChunkData)
	if err != nil {
		errResponse := structs.Response{}
		errResponse.Completed = true
		errResponse.TaskID = getFileFromMythic.Task.ID
		errResponse.UserOutput = fmt.Sprintf("Failed to parse message response from Mythic: %s", err.Error())
		getFileFromMythic.Task.Job.SendResponses <- errResponse
		getFileFromMythic.ReceivedChunkChannel <- make([]byte, 0)
		return
	}
	getFileFromMythic.ReceivedChunkChannel <- decoded

	// Track percentage completion
	lastPercentCompleteNotified := 0
	if fileUploadMsgResponse.TotalChunks > 1 {
		for index := 2; index <= fileUploadMsgResponse.TotalChunks; index++ {
			if getFileFromMythic.Task.ShouldStop() {
				getFileFromMythic.ReceivedChunkChannel <- make([]byte, 0)
				return
			}

			// Request the next chunk
			fileUploadMsg.Upload.ChunkNum = index
			getFileFromMythic.Task.Job.SendResponses <- fileUploadMsg

			// Get the response
			rawData := <-getFileFromMythic.FileTransferResponse
			fileUploadMsgResponse = structs.FileUploadMessageResponse{}
			err := json.Unmarshal(rawData, &fileUploadMsgResponse)
			if err != nil {
				errResponse := structs.Response{}
				errResponse.Completed = true
				errResponse.TaskID = getFileFromMythic.Task.ID
				errResponse.UserOutput = fmt.Sprintf("Failed to parse message response from Mythic: %s", err.Error())
				getFileFromMythic.Task.Job.SendResponses <- errResponse
				getFileFromMythic.ReceivedChunkChannel <- make([]byte, 0)
				return
			}

			// Decode and send the chunk
			decoded, err := base64.StdEncoding.DecodeString(fileUploadMsgResponse.ChunkData)
			if err != nil {
				errResponse := structs.Response{}
				errResponse.Completed = true
				errResponse.TaskID = getFileFromMythic.Task.ID
				errResponse.UserOutput = fmt.Sprintf("Failed to parse message response from Mythic: %s", err.Error())
				getFileFromMythic.Task.Job.SendResponses <- errResponse
				getFileFromMythic.ReceivedChunkChannel <- make([]byte, 0)
				return
			}
			getFileFromMythic.ReceivedChunkChannel <- decoded

			newPercentComplete := ((index * 100) / fileUploadMsgResponse.TotalChunks)
			if newPercentComplete/10 > lastPercentCompleteNotified && getFileFromMythic.SendUserStatusUpdates {
				response := structs.Response{}
				response.Completed = false
				response.TaskID = getFileFromMythic.Task.ID
				response.UserOutput = fmt.Sprintf("File Transfer Update: %d%% complete\n", newPercentComplete)
				getFileFromMythic.Task.Job.SendResponses <- response
				lastPercentCompleteNotified = newPercentComplete / 10
			}
		}
	}
	// Signal that we're done
	getFileFromMythic.ReceivedChunkChannel <- make([]byte, 0)
}
