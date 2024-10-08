.PHONY: clean kernel docker-image

KERNEL_FLAVOR ?=

clean:
	rm -rf out/*

docker-image:
	docker build -t obolnetwork/alpine-sev-builder .

kernel: docker-image
	mkdir -p out
	chmod 777 out
	docker run -it --rm -v $(PWD)/out:/src/out obolnetwork/alpine-sev-builder:latest $(KERNEL_FLAVOR)

