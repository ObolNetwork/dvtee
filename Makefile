.PHONY: clean kernel docker-image out-dir kernel-checksum just-kernel just-initramfs provision-installer run-installer initramfs-first-boot

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

initramfs-first-boot: out-dir docker-image
	docker run -it --rm -v $(PWD)/out:/src/out -v $(PWD)/vm-scripts/crypto_key.bin:/crypto_keyfile.bin obolnetwork/alpine-sev-builder:latest initramfs

initramfs-runtime: out-dir docker-image
	docker run -it --rm -v $(PWD)/out:/src/out -v $(PWD)/vm-scripts/crypto_key.bin:/crypto_keyfile.bin obolnetwork/alpine-sev-builder:latest initramfs-runtime

provision-installer:
	cd vm-scripts
	bash provision-installer.sh
	cd ..

run-installer:
	cd vm-scripts
	bash run-installer.sh
	cd ..
