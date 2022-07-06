
SUBDIRS := examples

%.pb.go: %.proto
	protoc \
		-I. \
		--go_out=paths=source_relative:. \
		$<

./api/.proto.stamp: api/client.pb.go api/signing.pb.go
	touch $@

main: 
	go build .

test:
	go test .

all: *.go ./api/.proto.stamp examples

$(SUBDIRS):
	$(MAKE) -C $@

.PHONY: all $(SUBDIRS)
