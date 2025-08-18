This document describes the release process for NGINX Unit and as such is
likely only of interest to NGINX Unit maintainers.

# Create a preparatory branch

You should create a new branch for doing this work. E.g.

    $ git checkout -b x.y[.z]-prep master


# Create a set of commits

## unitctl

Create a commit that updates the version of tools/unitctl. There are a
few places where this needs updating, find them with

    $ grep -rn x.y.z tools/unitctl/

See 3144710fe for an example.

## unit-openapi.yaml

Create a commit that updates the version in docs/unit-openapi.yaml

See 4d627c8f8 for an example.

## Dockerfiles

Create a commit that generates new dockerfiles.

    $ cd pkg/docker
    $ make clean
    $ make dockerfiles

    $ git rm/add as required

See f7771378f for an example.

## changes.xml

Create a commit that updates the docs/changes.xml for this release.

As well as adding the various entries also update the 'date' and 'time'
fields.

## Generate the CHANGES file

    $ make -C docs/ changes && mv build/CHANGES .

See 24ed91f40 for an example.


# Merge it

These should be the last commits into the repository before the release
is tagged.


# Tag the release

Once the above has been merged you can tag it with the new version. For
this we create an annotated tag. E.g. On master

    $ git tag -a -m "Unit 1.33.0 release." 1.33.0

This should create a new tag object pointing to the "CHANGES" commit.

The tag can be pushed just as the branch is. E.g.

    $ git push <upstream> 1.33.0


# A new 'Release'

After a while the new release should show up at
<https://github.com/nginx/unit/releases>


# Tarball

We need to publish an archive of the source and a checksum.

    $ cd pkg
    $ make dist
    $ rsync -tv unit-X.Y.Z.tar.* dev:/data/www/unit.nginx.org/download/


# Docs

The unit-docs repository needs a copy of CHANGES under
source/CHANGES.txt


# Post release

Immediately after release we should bump the version of Unit by editing
the version file and docs/changes.xml to add a new changes header.

See e67d74332 for an example.
