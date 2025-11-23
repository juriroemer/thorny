.DEFAULT_GOAL := run

run:
	go run .

build:
	go build .

br:
	go build .
	./thorny $(ARGS)

t:
	rsync -av --delete . [user@host:/path]