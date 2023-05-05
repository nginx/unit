Unit-Wasm demo
==============
## 1. Docker image unit:wasm
Create a Docker image that includes the Wasm module for Unit based on
[PR902](https://github.com/nginx/unit/pull/902).

```
docker build --no-cache -t unit:wasm -f unit-wasm.Dockerfile .
```
This image is based on the Docker Official Images for Unit 1.30 with a fresh
build of unitd and the experimental Wasm module. Wasmtime is included as a
shared object.

## 2. Docker image unit:demo-wasm

Create a second Docker image as a 'hello world' Wasm application.

```
docker build -t unit:demo-wasm -f demo-wasm.Dockerfile .
```
This image is based on the new `unit:wasm` image created above. It includes
a demo application written in C and compiled to wasm.

## 3. Run the demo

```
docker run -d -p 9000:80 unit:demo-wasm
curl localhost:9000
curl localhost:9000/wasm
```
