.ONESHELL: target/dist/release_notes.md
target/dist/release_notes.md: target/dist target/dist/SHA256SUMS
	$(info $(M) building release notes) @
	$Q echo "# Release Notes" > target/dist/release_notes.md
	echo '## SHA256 Checksums' >> target/dist/release_notes.md
	echo '```' >> target/dist/release_notes.md
	cat target/dist/SHA256SUMS >> target/dist/release_notes.md
	echo '```' >> target/dist/release_notes.md

.PHONY: release-notes
release-notes: target/dist/release_notes.md ## Build release notes

.PHONY: version
version: ## Outputs the current version
	$Q echo "Version: $(VERSION)"

.PHONY: version-update
.ONESHELL: version-update
version-update: ## Prompts for a new version
	$(info $(M) updating repository to new version) @
	$Q echo "  last committed version: $(LAST_VERSION)"
	$Q echo "  Cargo.toml file version : $(VERSION)"
	read -p "  Enter new version in the format (MAJOR.MINOR.PATCH): " version
	$Q echo "$$version" | $(GREP) -qE '^[0-9]+\.[0-9]+\.[0-9]+-?.*$$' || \
		(echo "invalid version identifier: $$version" && exit 1) && \
	$(SED) -i "s/^version\s*=.*$$/version = \"$$version\"/" \
		$(CURDIR)/unit-client-rs/Cargo.toml
	$(SED) -i "s/^version\s*=.*$$/version = \"$$version\"/" \
		$(CURDIR)/unitctl/Cargo.toml
	$(SED) -i "s/^version\s*=.*$$/version = \"$$version\"/" \
		$(CURDIR)/unit-openapi/Cargo.toml
	$(SED) -i "s/^\s*\"packageVersion\":\s*.*$$/  \"packageVersion\": \"$$version\",/" \
		$(CURDIR)/openapi-config.json
	@ VERSION=$(shell $(GREP) -Po '^version\s+=\s+"\K.*?(?=")' \
		$(CURDIR)/unitctl/Cargo.toml)

.PHONY: version-release
.ONESHELL: version-release
version-release: ## Change from a pre-release to full release version
	$Q echo "$(VERSION)" | $(GREP) -qE '^[0-9]+\.[0-9]+\.[0-9]+-beta$$' || \
		(echo "invalid version identifier - must contain suffix -beta: $(VERSION)" && exit 1)
	export NEW_VERSION="$(shell echo $(VERSION) | $(SED) -e 's/-beta$$//')"
	$(SED) -i "s/^version\s*=.*$$/version = \"$$NEW_VERSION\"/" \
		$(CURDIR)/unit-client-rs/Cargo.toml
	$(SED) -i "s/^version\s*=.*$$/version = \"$$NEW_VERSION\"/" \
		$(CURDIR)/unitctl/Cargo.toml
	$(SED) -i "s/^version\s*=.*$$/version = \"$$NEW_VERSION\"/" \
		$(CURDIR)/unit-openapi/Cargo.toml
	$(SED) -i "s/^\s*\"packageVersion\":\s*.*$$/  \"packageVersion\": \"$$NEW_VERSION\",/" \
		$(CURDIR)/openapi-config.json
	@ VERSION=$(shell $(GREP) -Po '^version\s+=\s+"\K.*?(?=")' \
		$(CURDIR)/unitctl/Cargo.toml)

.PHONY: cargo-release
cargo-release: ## Releases a new version to crates.io
	$(info $(M) releasing version $(VERSION) to crates.io) @
	$Q $(CARGO) publish
