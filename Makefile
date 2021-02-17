project = sniffer
version = v0.0
head = \\033[34m
end = \\033[0m

all:
	@echo -e $(head)"[Info]"$(end)
	@echo "Projcet: $(project)"
	@echo "Version: $(version)"
	@echo

	@echo -e $(head)"[Golnag Compile]"$(end)
	go build -ldflags "-s -w" -o $(project) main.go
	@echo

	@echo -e $(head)"[UPX Compression]"$(end)
	upx -f -9 $(project)
	@echo

	@echo -e $(head)"[Create RPM]"$(end)
	@mv $(project) build/bin/$(project)
	@cp $(project).yml build/conf/$(project).yml
	@sed -i "s/version:.*/version: \""$(version)"\"/" build/nfpm.yaml
	@cd build && nfpm pkg -p rpm -t rpm

