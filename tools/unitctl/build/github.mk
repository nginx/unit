.PHONY: gh-make-release
.ONESHELL: gh-make-release
gh-make-release:
ifndef CI
	$(error must be running in CI)
endif
ifneq ($(shell git rev-parse --abbrev-ref HEAD),release-v$(VERSION))
	$(error must be running on release-v$(VERSION) branch)
endif
	$(info $(M) updating files with release version [$(GIT_BRANCH)]) @
	git commit -m "ci: update files to version $(VERSION)" \
		Cargo.toml pkg/brew/$(PACKAGE_NAME).rb
	git push origin "release-v$(VERSION)"
	git tag -a "v$(VERSION)" -m "ci: tagging v$(VERSION)"
	git push origin --tags
	gh release create "v$(VERSION)" \
		--title "v$(VERSION)" \
		--notes-file $(CURDIR)/target/dist/release_notes.md \
		$(CURDIR)/target/dist/*.gz \
		$(CURDIR)/target/dist/*.deb \
		$(CURDIR)/target/dist/*.rpm \
		$(CURDIR)/target/dist/SHA256SUMS
