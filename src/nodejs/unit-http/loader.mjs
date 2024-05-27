// must be ran as part of a --loader or --experimental-loader param
export async function resolve(specifier, context, defaultResolver) {
    switch (specifier) {
        case "websocket":
        case "node:websocket":
            return {
                url: new URL("./websocket.js", import.meta.url).href,
                format: "commonjs",
                shortCircuit: true,
            }

        case "http":
        case "node:http":
            return {
                url: new URL("./http.js", import.meta.url).href,
                format: "commonjs",
                shortCircuit: true,
            }
    }

    return defaultResolver(specifier, context, defaultResolver)
}
