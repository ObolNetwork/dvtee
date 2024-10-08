.PHONY: clean kernel docker-image

clean:
	rm -rf out/*

docker-image:
	docker build -t obolnetwork/alpine-sev-builder .

out-dir:
	mkdir -p out
	chmod 777 out

kernel-checksum: out-dir docker-image
	docker run -it --rm -v $(PWD)/out:/src/out obolnetwork/alpine-sev-builder:latest checksum

kernel: out-dir docker-image
	docker run -it --rm -v $(PWD)/out:/src/out obolnetwork/alpine-sev-builder:latest complete

just-kernel: out-dir docker-image	
	docker run -it --rm -v $(PWD)/out:/src/out obolnetwork/alpine-sev-builder:latest

just-initramfs: out-dir docker-image
	docker run -it --rm -v $(PWD)/out:/src/out obolnetwork/alpine-sev-builder:latest initramfs
