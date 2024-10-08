.PHONY: clean kernel docker-image

clean:
	rm -rf out/*

docker-image:
	docker build -t obolnetwork/alpine-sev-builder .

kernel: docker-image
	mkdir -p out
	docker run -it --rm -v $(PWD)/out:/src/out obolnetwork/alpine-sev-builder:latest
