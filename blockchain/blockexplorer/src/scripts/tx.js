import b64 from "base64-js"

// See https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding
export const encodeBase64 = (str, encoding = 'utf-8') => {
  let bytes = new (TextEncoder || TextEncoderLite)(encoding).encode(str)
  return b64.fromByteArray(bytes)
}

// See https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding
export const decodeBase64 = (str, encoding = 'utf-8') => {
  let bytes = b64.toByteArray(str);
  return new (TextDecoder || TextDecoderLite)(encoding).decode(bytes)
}

export const decodeTx = (base64str) => {
  return decodeBase64(base64str)
}
