# fakeTunnel Makefile
# 适用于本地开发、测试、构建、交叉编译与安装

# Go 工具链检测：优先使用仓库内解压的 .tools/go，其次使用系统 PATH 中的 go
ifeq ($(wildcard $(CURDIR)/.tools/go/bin/go),)
  GO ?= go
  GOFMT ?= gofmt
else
  GO ?= $(CURDIR)/.tools/go/bin/go
  GOFMT ?= $(CURDIR)/.tools/go/bin/gofmt
endif

# 编译参数与变量
BIN_DIR       ?= bin
CGO_ENABLED   ?= 0
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME    ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS       ?= -s -w -X main.version=$(VERSION)
GOFLAGS       ?=
INSTALL_PREFIX ?= /usr/local

# 目标二进制文件与源码文件依赖
EDGE_BIN      = $(BIN_DIR)/edge
AGENT_BIN     = $(BIN_DIR)/agent
CLI_BIN       = $(BIN_DIR)/faketunnel
GO_SRCS       = $(shell find . -type f -name '*.go' -not -path './.tools/*')

.PHONY: all build build-all edge agent faketunnel cli test test-unit test-itest test-cover vet fmt fmt-check clean install uninstall cross-all cross-linux-amd64 cross-linux-arm64 cross-darwin-amd64 cross-darwin-arm64 cross-windows-amd64 help

# 默认目标：编译所有二进制
all: build

# 编译所有程序
build: edge agent faketunnel
build-all: build

# 编译 Edge 服务端
edge: $(EDGE_BIN)
$(EDGE_BIN): $(GO_SRCS)
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(EDGE_BIN) ./cmd/edge

# 编译 Agent 客户端
agent: $(AGENT_BIN)
$(AGENT_BIN): $(GO_SRCS)
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(AGENT_BIN) ./cmd/agent

# 编译 Admin CLI (faketunnel)
faketunnel: $(CLI_BIN)
cli: faketunnel
$(CLI_BIN): $(GO_SRCS)
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(CLI_BIN) ./cmd/faketunnel

# 运行所有测试
test:
	$(GO) test -v ./...

# 仅运行轻量单元测试（排除耗时端到端测试）
test-unit:
	$(GO) test -v $(shell $(GO) list ./... | grep -v '/internal/itest')

# 运行集成与端到端测试
test-itest:
	$(GO) test -v -count=1 ./internal/itest

# 测试覆盖率
test-cover:
	@mkdir -p $(BIN_DIR)
	$(GO) test -coverprofile=$(BIN_DIR)/coverage.out ./...
	$(GO) tool cover -func=$(BIN_DIR)/coverage.out

# 代码静态检查
vet:
	$(GO) vet ./...

# 代码格式化
fmt:
	$(GO) fmt ./...

# 检查代码格式是否整洁
fmt-check:
	@files=$$($(GOFMT) -l $(shell find . -type f -name '*.go' -not -path './.tools/*')); \
	if [ -n "$$files" ]; then \
		echo "Following files are not formatted:"; \
		echo "$$files"; \
		exit 1; \
	fi

# 清理构建产物与临时文件
clean:
	rm -rf $(BIN_DIR)

# 安装二进制到系统目录
install: build
	install -d $(DESTDIR)$(INSTALL_PREFIX)/bin
	install -m 755 $(EDGE_BIN) $(DESTDIR)$(INSTALL_PREFIX)/bin/
	install -m 755 $(AGENT_BIN) $(DESTDIR)$(INSTALL_PREFIX)/bin/
	install -m 755 $(CLI_BIN) $(DESTDIR)$(INSTALL_PREFIX)/bin/

# 卸载二进制
uninstall:
	rm -f $(DESTDIR)$(INSTALL_PREFIX)/bin/edge
	rm -f $(DESTDIR)$(INSTALL_PREFIX)/bin/agent
	rm -f $(DESTDIR)$(INSTALL_PREFIX)/bin/faketunnel

# 交叉编译目标
cross-all: cross-linux-amd64 cross-linux-arm64 cross-darwin-amd64 cross-darwin-arm64 cross-windows-amd64

cross-linux-amd64:
	@mkdir -p $(BIN_DIR)/linux_amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/linux_amd64/edge ./cmd/edge
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/linux_amd64/agent ./cmd/agent
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/linux_amd64/faketunnel ./cmd/faketunnel

cross-linux-arm64:
	@mkdir -p $(BIN_DIR)/linux_arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/linux_arm64/edge ./cmd/edge
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/linux_arm64/agent ./cmd/agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/linux_arm64/faketunnel ./cmd/faketunnel

cross-darwin-amd64:
	@mkdir -p $(BIN_DIR)/darwin_amd64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/darwin_amd64/edge ./cmd/edge
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/darwin_amd64/agent ./cmd/agent
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/darwin_amd64/faketunnel ./cmd/faketunnel

cross-darwin-arm64:
	@mkdir -p $(BIN_DIR)/darwin_arm64
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/darwin_arm64/edge ./cmd/edge
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/darwin_arm64/agent ./cmd/agent
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/darwin_arm64/faketunnel ./cmd/faketunnel

cross-windows-amd64:
	@mkdir -p $(BIN_DIR)/windows_amd64
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/windows_amd64/edge.exe ./cmd/edge
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/windows_amd64/agent.exe ./cmd/agent
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/windows_amd64/faketunnel.exe ./cmd/faketunnel

help:
	@echo "fakeTunnel 构建与管理命令帮助:"
	@echo "  make build         - 编译所有二进制文件 (bin/edge, bin/agent, bin/faketunnel)"
	@echo "  make edge          - 编译 Edge 服务端"
	@echo "  make agent         - 编译 Agent 客户端"
	@echo "  make faketunnel    - 编译 Admin CLI 工具"
	@echo "  make test          - 运行完整测试套件"
	@echo "  make test-unit     - 仅运行单元测试 (排除长耗时集成测试)"
	@echo "  make test-itest    - 运行端到端与集成测试"
	@echo "  make vet           - 运行 go vet 代码静态检查"
	@echo "  make fmt           - 格式化代码"
	@echo "  make clean         - 清理构建产物目录"
	@echo "  make install       - 安装二进制至 $(INSTALL_PREFIX)/bin"
	@echo "  make cross-all     - 交叉编译所有主流平台二进制"
