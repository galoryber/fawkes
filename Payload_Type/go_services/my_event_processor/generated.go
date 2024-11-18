// Code generated by github.com/Khan/genqlient, DO NOT EDIT.

package my_event_processor

import (
	"context"

	"github.com/Khan/genqlient/graphql"
)

// CreateNewTagInsert_tag_oneTag includes the requested fields of the GraphQL type tag.
// The GraphQL type's documentation follows.
//
// columns and relationships of "tag"
type CreateNewTagInsert_tag_oneTag struct {
	Id int `json:"id"`
}

// GetId returns CreateNewTagInsert_tag_oneTag.Id, and is useful for accessing the field via an interface.
func (v *CreateNewTagInsert_tag_oneTag) GetId() int { return v.Id }

// CreateNewTagResponse is returned by CreateNewTag on success.
type CreateNewTagResponse struct {
	// insert a single row into the table: "tag"
	Insert_tag_one CreateNewTagInsert_tag_oneTag `json:"insert_tag_one"`
}

// GetInsert_tag_one returns CreateNewTagResponse.Insert_tag_one, and is useful for accessing the field via an interface.
func (v *CreateNewTagResponse) GetInsert_tag_one() CreateNewTagInsert_tag_oneTag {
	return v.Insert_tag_one
}

// CreateNewTagTypeInsert_tagtype_oneTagtype includes the requested fields of the GraphQL type tagtype.
// The GraphQL type's documentation follows.
//
// columns and relationships of "tagtype"
type CreateNewTagTypeInsert_tagtype_oneTagtype struct {
	Id int `json:"id"`
}

// GetId returns CreateNewTagTypeInsert_tagtype_oneTagtype.Id, and is useful for accessing the field via an interface.
func (v *CreateNewTagTypeInsert_tagtype_oneTagtype) GetId() int { return v.Id }

// CreateNewTagTypeResponse is returned by CreateNewTagType on success.
type CreateNewTagTypeResponse struct {
	// insert a single row into the table: "tagtype"
	Insert_tagtype_one CreateNewTagTypeInsert_tagtype_oneTagtype `json:"insert_tagtype_one"`
}

// GetInsert_tagtype_one returns CreateNewTagTypeResponse.Insert_tagtype_one, and is useful for accessing the field via an interface.
func (v *CreateNewTagTypeResponse) GetInsert_tagtype_one() CreateNewTagTypeInsert_tagtype_oneTagtype {
	return v.Insert_tagtype_one
}

// GetPayloadDataPayload includes the requested fields of the GraphQL type payload.
// The GraphQL type's documentation follows.
//
// columns and relationships of "payload"
type GetPayloadDataPayload struct {
	// An object relationship
	Filemetum GetPayloadDataPayloadFilemetumFilemeta `json:"filemetum"`
}

// GetFilemetum returns GetPayloadDataPayload.Filemetum, and is useful for accessing the field via an interface.
func (v *GetPayloadDataPayload) GetFilemetum() GetPayloadDataPayloadFilemetumFilemeta {
	return v.Filemetum
}

// GetPayloadDataPayloadFilemetumFilemeta includes the requested fields of the GraphQL type filemeta.
// The GraphQL type's documentation follows.
//
// columns and relationships of "filemeta"
type GetPayloadDataPayloadFilemetumFilemeta struct {
	Id int `json:"id"`
}

// GetId returns GetPayloadDataPayloadFilemetumFilemeta.Id, and is useful for accessing the field via an interface.
func (v *GetPayloadDataPayloadFilemetumFilemeta) GetId() int { return v.Id }

// GetPayloadDataResponse is returned by GetPayloadData on success.
type GetPayloadDataResponse struct {
	// fetch data from the table: "payload"
	Payload []GetPayloadDataPayload `json:"payload"`
}

// GetPayload returns GetPayloadDataResponse.Payload, and is useful for accessing the field via an interface.
func (v *GetPayloadDataResponse) GetPayload() []GetPayloadDataPayload { return v.Payload }

// UpdateCallbackResponse is returned by UpdateCallback on success.
type UpdateCallbackResponse struct {
	UpdateCallback UpdateCallbackUpdateCallbackUpdateCallbackOutput `json:"updateCallback"`
}

// GetUpdateCallback returns UpdateCallbackResponse.UpdateCallback, and is useful for accessing the field via an interface.
func (v *UpdateCallbackResponse) GetUpdateCallback() UpdateCallbackUpdateCallbackUpdateCallbackOutput {
	return v.UpdateCallback
}

// UpdateCallbackUpdateCallbackUpdateCallbackOutput includes the requested fields of the GraphQL type updateCallbackOutput.
type UpdateCallbackUpdateCallbackUpdateCallbackOutput struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

// GetStatus returns UpdateCallbackUpdateCallbackUpdateCallbackOutput.Status, and is useful for accessing the field via an interface.
func (v *UpdateCallbackUpdateCallbackUpdateCallbackOutput) GetStatus() string { return v.Status }

// GetError returns UpdateCallbackUpdateCallbackUpdateCallbackOutput.Error, and is useful for accessing the field via an interface.
func (v *UpdateCallbackUpdateCallbackUpdateCallbackOutput) GetError() string { return v.Error }

// __CreateNewTagInput is used internally by genqlient
type __CreateNewTagInput struct {
	Tagtype_id int                    `json:"tagtype_id"`
	Source     string                 `json:"source"`
	Url        string                 `json:"url"`
	Data       map[string]interface{} `json:"data"`
	Task_id    int                    `json:"task_id"`
}

// GetTagtype_id returns __CreateNewTagInput.Tagtype_id, and is useful for accessing the field via an interface.
func (v *__CreateNewTagInput) GetTagtype_id() int { return v.Tagtype_id }

// GetSource returns __CreateNewTagInput.Source, and is useful for accessing the field via an interface.
func (v *__CreateNewTagInput) GetSource() string { return v.Source }

// GetUrl returns __CreateNewTagInput.Url, and is useful for accessing the field via an interface.
func (v *__CreateNewTagInput) GetUrl() string { return v.Url }

// GetData returns __CreateNewTagInput.Data, and is useful for accessing the field via an interface.
func (v *__CreateNewTagInput) GetData() map[string]interface{} { return v.Data }

// GetTask_id returns __CreateNewTagInput.Task_id, and is useful for accessing the field via an interface.
func (v *__CreateNewTagInput) GetTask_id() int { return v.Task_id }

// __CreateNewTagTypeInput is used internally by genqlient
type __CreateNewTagTypeInput struct {
	Color       string `json:"color"`
	Description string `json:"description"`
	Name        string `json:"name"`
}

// GetColor returns __CreateNewTagTypeInput.Color, and is useful for accessing the field via an interface.
func (v *__CreateNewTagTypeInput) GetColor() string { return v.Color }

// GetDescription returns __CreateNewTagTypeInput.Description, and is useful for accessing the field via an interface.
func (v *__CreateNewTagTypeInput) GetDescription() string { return v.Description }

// GetName returns __CreateNewTagTypeInput.Name, and is useful for accessing the field via an interface.
func (v *__CreateNewTagTypeInput) GetName() string { return v.Name }

// __GetPayloadDataInput is used internally by genqlient
type __GetPayloadDataInput struct {
	Uuid string `json:"uuid"`
}

// GetUuid returns __GetPayloadDataInput.Uuid, and is useful for accessing the field via an interface.
func (v *__GetPayloadDataInput) GetUuid() string { return v.Uuid }

// __UpdateCallbackInput is used internally by genqlient
type __UpdateCallbackInput struct {
	Callback_display_id int    `json:"callback_display_id"`
	Description         string `json:"description"`
}

// GetCallback_display_id returns __UpdateCallbackInput.Callback_display_id, and is useful for accessing the field via an interface.
func (v *__UpdateCallbackInput) GetCallback_display_id() int { return v.Callback_display_id }

// GetDescription returns __UpdateCallbackInput.Description, and is useful for accessing the field via an interface.
func (v *__UpdateCallbackInput) GetDescription() string { return v.Description }

// __getTagTypesInput is used internally by genqlient
type __getTagTypesInput struct {
	Name string `json:"name"`
}

// GetName returns __getTagTypesInput.Name, and is useful for accessing the field via an interface.
func (v *__getTagTypesInput) GetName() string { return v.Name }

// getTagTypesResponse is returned by getTagTypes on success.
type getTagTypesResponse struct {
	// fetch data from the table: "tagtype"
	Tagtype []getTagTypesTagtype `json:"tagtype"`
}

// GetTagtype returns getTagTypesResponse.Tagtype, and is useful for accessing the field via an interface.
func (v *getTagTypesResponse) GetTagtype() []getTagTypesTagtype { return v.Tagtype }

// getTagTypesTagtype includes the requested fields of the GraphQL type tagtype.
// The GraphQL type's documentation follows.
//
// columns and relationships of "tagtype"
type getTagTypesTagtype struct {
	Id int `json:"id"`
}

// GetId returns getTagTypesTagtype.Id, and is useful for accessing the field via an interface.
func (v *getTagTypesTagtype) GetId() int { return v.Id }

// The query or mutation executed by CreateNewTag.
const CreateNewTag_Operation = `
mutation CreateNewTag ($tagtype_id: Int!, $source: String!, $url: String!, $data: jsonb!, $task_id: Int!) {
	insert_tag_one(object: {data:$data,source:$source,tagtype_id:$tagtype_id,url:$url,task_id:$task_id}) {
		id
	}
}
`

func CreateNewTag(
	ctx_ context.Context,
	client_ graphql.Client,
	tagtype_id int,
	source string,
	url string,
	data map[string]interface{},
	task_id int,
) (*CreateNewTagResponse, error) {
	req_ := &graphql.Request{
		OpName: "CreateNewTag",
		Query:  CreateNewTag_Operation,
		Variables: &__CreateNewTagInput{
			Tagtype_id: tagtype_id,
			Source:     source,
			Url:        url,
			Data:       data,
			Task_id:    task_id,
		},
	}
	var err_ error

	var data_ CreateNewTagResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by CreateNewTagType.
const CreateNewTagType_Operation = `
mutation CreateNewTagType ($color: String!, $description: String!, $name: String!) {
	insert_tagtype_one(object: {color:$color,description:$description,name:$name}, on_conflict: {constraint:tagtype_name_operation_id_key,update_columns:color}) {
		id
	}
}
`

func CreateNewTagType(
	ctx_ context.Context,
	client_ graphql.Client,
	color string,
	description string,
	name string,
) (*CreateNewTagTypeResponse, error) {
	req_ := &graphql.Request{
		OpName: "CreateNewTagType",
		Query:  CreateNewTagType_Operation,
		Variables: &__CreateNewTagTypeInput{
			Color:       color,
			Description: description,
			Name:        name,
		},
	}
	var err_ error

	var data_ CreateNewTagTypeResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by GetPayloadData.
const GetPayloadData_Operation = `
query GetPayloadData ($uuid: String!) {
	payload(where: {uuid:{_eq:$uuid}}) {
		filemetum {
			id
		}
	}
}
`

func GetPayloadData(
	ctx_ context.Context,
	client_ graphql.Client,
	uuid string,
) (*GetPayloadDataResponse, error) {
	req_ := &graphql.Request{
		OpName: "GetPayloadData",
		Query:  GetPayloadData_Operation,
		Variables: &__GetPayloadDataInput{
			Uuid: uuid,
		},
	}
	var err_ error

	var data_ GetPayloadDataResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by UpdateCallback.
const UpdateCallback_Operation = `
mutation UpdateCallback ($callback_display_id: Int, $description: String) {
	updateCallback(input: {callback_display_id:$callback_display_id,description:$description}) {
		status
		error
	}
}
`

func UpdateCallback(
	ctx_ context.Context,
	client_ graphql.Client,
	callback_display_id int,
	description string,
) (*UpdateCallbackResponse, error) {
	req_ := &graphql.Request{
		OpName: "UpdateCallback",
		Query:  UpdateCallback_Operation,
		Variables: &__UpdateCallbackInput{
			Callback_display_id: callback_display_id,
			Description:         description,
		},
	}
	var err_ error

	var data_ UpdateCallbackResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by getTagTypes.
const getTagTypes_Operation = `
query getTagTypes ($name: String!) {
	tagtype(where: {name:{_eq:$name}}) {
		id
	}
}
`

func getTagTypes(
	ctx_ context.Context,
	client_ graphql.Client,
	name string,
) (*getTagTypesResponse, error) {
	req_ := &graphql.Request{
		OpName: "getTagTypes",
		Query:  getTagTypes_Operation,
		Variables: &__getTagTypesInput{
			Name: name,
		},
	}
	var err_ error

	var data_ getTagTypesResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}
