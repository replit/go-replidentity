
SUBDIRS := examples

%.pb.go: %.proto
	protoc \
		-I. \
		--go_out=paths=source_relative:. \
		$<

./protos/external/goval/api/.proto.stamp: protos/external/goval/api/client.pb.go protos/external/goval/api/signing.pb.go
	touch $@

main: ./protos/external/goval/api/.proto.stamp
	go build .

test: ./protos/external/goval/api/.proto.stamp
	go test .

all: *.go ./protos/external/goval/api/.proto.stamp examples

$(SUBDIRS):
	$(MAKE) -C $@

.PHONY: all $(SUBDIRS)
