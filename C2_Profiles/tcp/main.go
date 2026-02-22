package main

import (
	c2functions "MyContainer/tcp/c2functions"
	"github.com/MythicMeta/MythicContainer"
)

func main() {
	c2functions.Initialize()
	MythicContainer.StartAndRunForever([]MythicContainer.MythicServices{
		MythicContainer.MythicServiceC2,
	})
}
