<template lang="pug">
menu.app-menu
  .app-menu-main
    tm-list-item(to="/" exact @click.native="close" title="Overview")
    tm-list-item(to="/blocks" exact @click.native="close" :title="`Blocks (${totalBlocks})`")
    tm-list-item(to="/nodes" exact @click.native="close" :title="`Full Nodes (${nodes.length})`")
    //tm-list-item(to="/validators" @click.native="close" :title="`Validators (${votingValidators})`" v-bind:class="{ 'active': isValidatorPage }")
    //tm-list-item(to="/validators-revoked" @click.native="close" :title="`Revoked Validators (${revokedValidators})`")
    tm-list-item(to="/search" exact @click.native="close" title="Search")
</template>

<script>
import { mapGetters } from "vuex"
import noScroll from "no-scroll"
import votingValidators from "scripts/votingValidators"
import { TmListItem, TmPart } from "@tendermint/ui"
export default {
  name: "app-menu",
  components: {
    TmListItem,
    TmPart
  },
  computed: {
    ...mapGetters(["proposals", "nodes", "validators", "totalBlocks"]),
    proposalAlerts() {
      return this.proposals.filter(p => p.flags.read === false).length
    },
    isValidatorPage() {
      return this.$route.params.validator
    },
    votingValidators() {
      return votingValidators(this.validators).length
    },
    revokedValidators() {
      return this.validators.length - votingValidators(this.validators).length
    }
  },
  methods: {
    close() {
      this.$store.commit("setActiveMenu", "")
      noScroll.off()
    }
  }
}
</script>

<style lang="stylus">
@require '../styles/variables.styl'

.app-menu
  background var(--app-fg)
  z-index z(appMenu)
  user-select none
  display flex
  flex-flow column nowrap

  .app-menu-main
    flex 1
    position relative // for perfect-scrollbar

    .tm-li
      border-bottom 1px solid var(--bc-dim)
  .tm-part-main
    padding 0
@media screen and (max-width:1023px)
  .app-menu
    position fixed
    top 3rem
    left 0
    bottom 0
    width 100vw
    background var(--app-bg)
    user-select none

@media screen and (min-width: 1024px)
  .app-menu
    flex 1

</style>
