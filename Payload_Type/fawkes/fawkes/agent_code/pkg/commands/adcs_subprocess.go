package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type adcsRequestSubprocessParams struct {
	CAName   string `json:"ca_name"`
	Template string `json:"template"`
	AltName  string `json:"alt_name"`
	CSRDER   string `json:"csr_der"` // base64-encoded
}

type adcsRequestSubprocessResult struct {
	Disposition        uint32 `json:"disposition"`
	RequestID          uint32 `json:"request_id"`
	DispositionMessage string `json:"disposition_message"`
	EncodedCert        string `json:"encoded_cert"` // base64-encoded DER
}

type adcsEditFlagsSubprocessParams struct {
	CAName string `json:"ca_name"`
}

type adcsEditFlagsSubprocessResult struct {
	EditFlags uint32 `json:"edit_flags"`
}

func rpcHelperAdcsRequest(req rpcHelperRequest) (json.RawMessage, error) {
	var p adcsRequestSubprocessParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid adcs-request params: %v", err)
	}

	csrDER, err := base64.StdEncoding.DecodeString(p.CSRDER)
	if err != nil {
		return nil, fmt.Errorf("decode CSR: %v", err)
	}

	ctx, cancel, cred, credErr := rpcHelperCredAndContext(req)
	if credErr != nil {
		return nil, fmt.Errorf("credential setup: %v", credErr)
	}
	defer cancel()

	resp, err := adcsSubmitCSR(ctx, req.Server, p.CAName, p.Template, p.AltName, csrDER, cred)
	if err != nil {
		return nil, err
	}

	result := adcsRequestSubprocessResult{
		Disposition: resp.Disposition,
		RequestID:   resp.RequestID,
	}

	if resp.DispositionMessage != nil && len(resp.DispositionMessage.Buffer) > 0 {
		result.DispositionMessage = adcsDecodeUTF16(resp.DispositionMessage.Buffer)
	}

	if resp.EncodedCert != nil && len(resp.EncodedCert.Buffer) > 0 {
		result.EncodedCert = base64.StdEncoding.EncodeToString(resp.EncodedCert.Buffer)
	}

	out, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal result: %v", err)
	}
	return out, nil
}

func rpcHelperAdcsEditFlags(req rpcHelperRequest) (json.RawMessage, error) {
	var p adcsEditFlagsSubprocessParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid adcs-editflags params: %v", err)
	}

	ctx, cancel, cred, credErr := rpcHelperCredAndContext(req)
	if credErr != nil {
		return nil, fmt.Errorf("credential setup: %v", credErr)
	}
	defer cancel()

	flags, err := adcsQueryEditFlags(ctx, req.Server, p.CAName, cred)
	if err != nil {
		return nil, err
	}

	out, err := json.Marshal(adcsEditFlagsSubprocessResult{EditFlags: flags})
	if err != nil {
		return nil, fmt.Errorf("marshal result: %v", err)
	}
	return out, nil
}
