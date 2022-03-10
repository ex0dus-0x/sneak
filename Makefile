all:
	go build -o sneak cmd/sneak/main.go

clean:
	rm -f sneak
