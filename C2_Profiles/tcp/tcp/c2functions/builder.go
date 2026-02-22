package c2functions

import (
	c2structs "github.com/MythicMeta/MythicContainer/c2_structs"
)

var tcpc2definition = c2structs.C2Profile{
	Name:           "tcp",
	Author:         "@GlobeTechLLC",
	Description:    "Uses TCP for peer-to-peer agent communication. A child agent listens on a TCP port and a parent agent connects to it via the link command.",
	IsP2p:          true,
	IsServerRouted: false,
}

var tcpc2parameters = []c2structs.C2Parameter{
	{
		Name:          "port",
		Description:   "TCP port for the agent to listen on",
		DefaultValue:  7777,
		ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER,
		Required:      true,
		VerifierRegex: "^[0-9]+$",
	},
	{
		Name:          "AESPSK",
		Description:   "Encryption Type",
		DefaultValue:  "aes256_hmac",
		ParameterType: c2structs.C2_PARAMETER_TYPE_CHOOSE_ONE,
		Required:      false,
		IsCryptoType:  true,
		Choices: []string{
			"aes256_hmac",
			"none",
		},
	},
	{
		Name:          "killdate",
		Description:   "Kill Date",
		DefaultValue:  365,
		ParameterType: c2structs.C2_PARAMETER_TYPE_DATE,
		Required:      false,
	},
}

func Initialize() {
	c2structs.AllC2Data.Get("tcp").AddC2Definition(tcpc2definition)
	c2structs.AllC2Data.Get("tcp").AddParameters(tcpc2parameters)
}
