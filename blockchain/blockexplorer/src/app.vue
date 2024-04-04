<template lang="pug">
#app
  tm-cookie-consent
  app-header
  #app-content
    router-view
    app-footer
</template>

<script>
import requestInterval from "request-interval"
import { mapGetters } from "vuex"
import { TmCookieConsent, TmModalError } from "@tendermint/ui"
import AppFooter from "./components/AppFooter"
import AppHeader from "./components/AppHeader"
import store from "./store/index"
export default {
  name: "app",
  components: {
    AppHeader,
    AppFooter,
    TmCookieConsent,
    TmModalError
  },
  computed: {
    ...mapGetters(["nodes"])
  },
  mounted() {
    this.$store.dispatch("getLastBlock")
    this.$store.dispatch("subNewBlock")
    this.$store.dispatch("subRoundStep")
    requestInterval(1000, () => this.$store.dispatch("getConsensusState"))
    this.$store.dispatch("getStatus")
    this.$store.dispatch("getNodes")
    this.$store.dispatch("getValidators")
  },
  store
}
</script>

<style lang="stylus" src="./styles/app.styl"></style>
<style lang="stylus">
  .tm-part
    max-width 100%
  .tm-part-main
   padding-right 0
  .tm-part-title
    font-size 14px
  .tm-page-header-text
    h2
      font-weight normal
  .tm-li-dl
    height 100%
    padding 0.5rem
  .tm-li-dt
    color var(--dim)
  .tm-li-dd
    white-space normal
    overflow auto
    word-break break-word
  @media screen and (min-width: 768px)
    .tm-part-container:last-child
      padding-bottom: 0
</style>
