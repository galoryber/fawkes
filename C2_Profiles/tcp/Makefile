BINARY_NAME?=main

build:
	CGO_ENABLED=0 go build -o ${BINARY_NAME} .
	cp ${BINARY_NAME} /

run:
	cp /${BINARY_NAME} .
	./${BINARY_NAME}
