DOCKER		:= sudo DOCKER_BUILDKIT=1 docker
IMAGE		:= libubiqclient-debian-package

deb:
	$(DOCKER) builder build --progress plain \
		-t $(IMAGE) -f package/Dockerfile .
	rm -rf package/build
	$(DOCKER) cp \
		$$(sudo docker create $(IMAGE)):/src/build \
		package
	sudo chown -R $$(id -u):$$(id -g) package/build
	mv package/build/*.deb package
	rm -rf package/build
	-$(DOCKER) rm $$($(DOCKER) ps -aq \
		-f ancestor=$(IMAGE) -f status=created)
	$(DOCKER) rmi $(IMAGE)
	-$(DOCKER) rmi $$($(DOCKER) images -aq -f dangling=true)
	-$(DOCKER) builder prune -f
