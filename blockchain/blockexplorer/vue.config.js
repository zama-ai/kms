const path = require("path")

function resolve(dir) {
  return path.join(__dirname, dir)
}

let markdown = require("markdown-it")({
  preset: "default",
  html: true,
  typographer: true,
  linkify: true,
  preprocess: (markdownIt, source) => source
})
module.exports = {
  chainWebpack: config => {
    config.resolve.alias
      .set("assets", resolve("src/assets"))
      .set("images", resolve("src/assets/images"))
      .set("comp", resolve("src/components"))
      .set("scripts", resolve("src/scripts"))
      .set("variables", resolve("src/styles/variables.styl"))
    config.module
      .rule("pdf")
      .test(/\.pdf/)
      .use("")
      .loader("file-loader")
    config.module
      .rule("markdown")
      .test(/\.md/)
      .use("")
      .loader("vue-markdown-loader")
      .options(markdown)
  },
  devServer: {
    proxy: 'http://localhost:36657'
  }
}
