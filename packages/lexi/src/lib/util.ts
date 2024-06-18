// convert a js object to and from a byte stream by stringifying and encoding it as an utf8 byte array
export const objToBytes = (obj: any): Uint8Array => new TextEncoder().encode(JSON.stringify(obj));
export const bytesToObj = (bytes: Uint8Array): any => JSON.parse(new TextDecoder().decode(bytes));
