
GO ?= go
GOFLAGS ?=
NAME ?= pvss
OUT_LIB ?= dist/lib
OUT_INCLUDE ?= dist/include
SRC := c_wrapper.go
LIB_BASENAME := lib$(NAME)

HOST_OS := $(shell $(GO) env GOOS)
HOST_ARCH := $(shell $(GO) env GOARCH)

ifeq ($(HOST_OS),windows)
HOST_EXT := dll
HOST_PREFIX :=
else ifeq ($(HOST_OS),darwin)
HOST_EXT := dylib
HOST_PREFIX := lib
else
HOST_EXT := so
HOST_PREFIX := lib
endif

LINUX_ARCH ?= amd64
DARWIN_ARCH ?= amd64
WINDOWS_ARCH ?= amd64

HOST_LIB := $(OUT_LIB)/$(LIB_BASENAME).$(HOST_EXT)
HOST_HDR := $(OUT_INCLUDE)/$(LIB_BASENAME).h

LINUX_EXT := so
DARWIN_EXT := dylib
WINDOWS_EXT := dll

.PHONY: test benchmark build build-linux build-darwin build-windows clean

define build_shared
	@mkdir -p $(OUT_LIB) $(OUT_INCLUDE)
	GOOS=$(1) GOARCH=$(2) CGO_ENABLED=1 $(GO) build $(GOFLAGS) -buildmode=c-shared -o $(OUT_LIB)/$(LIB_BASENAME).$(3) $(SRC)
	@mv $(OUT_LIB)/$(LIB_BASENAME).h $(OUT_INCLUDE)/$(LIB_BASENAME).h
endef

test:
	$(GO) test ./...

benchmark:
	$(GO) test ./pvss -bench=. -benchmem

build: $(HOST_LIB)
	@mv $(OUT_LIB)/$(LIB_BASENAME).h $(OUT_INCLUDE)/$(LIB_BASENAME).h

build-linux:
	$(call build_shared,linux,$(LINUX_ARCH),$(LINUX_EXT))

build-darwin:
	$(call build_shared,darwin,$(DARWIN_ARCH),$(DARWIN_EXT))

build-windows:
	$(call build_shared,windows,$(WINDOWS_ARCH),$(WINDOWS_EXT))

$(HOST_LIB):
	@mkdir -p $(OUT_LIB) $(OUT_INCLUDE)
	CGO_ENABLED=1 $(GO) build $(GOFLAGS) -buildmode=c-shared -o $@ $(SRC)

clean:
	rm -rf dist
