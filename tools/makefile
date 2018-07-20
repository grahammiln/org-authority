PLATFORMS := darwin/amd64 linux/amd64 linux/386 windows/amd64 windows/386

temp = $(subst /, ,$@)
os = $(word 1, $(temp))
arch = $(word 2, $(temp))

release: $(PLATFORMS)

$(PLATFORMS):
	GOOS=$(os) GOARCH=$(arch) go build -ldflags=-s -o 'dist/$(os)-$(arch)/oamake-root' src/oamake-root/oamake-root.go
	GOOS=$(os) GOARCH=$(arch) go build -ldflags=-s -o 'dist/$(os)-$(arch)/oamake-intermediate' src/oamake-intermediate/oamake-intermediate.go
	GOOS=$(os) GOARCH=$(arch) go build -ldflags=-s -o 'dist/$(os)-$(arch)/oamake-issuing' src/oamake-issuing/oamake-issuing.go

.PHONY: release $(PLATFORMS)
