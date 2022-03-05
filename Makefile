all:
	go build && go build cmd/sneak/main.go
	mv ./main ./sneak

clean:
	rm -f sneak
