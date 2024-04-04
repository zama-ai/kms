<template lang="pug">
tm-page(title=process.env.VUE_APP_NETWORK)
  tm-part(title='Testnet Data')
    tm-list-item(dt='Testnet Version' :dd='bc.status.node_info.network')
    // tm-list-item(dt='Tendermint Version' :dd='bc.status.node_info.version')
    tm-list-item(dt='Status' :dd='validatorsActive' :href="`${bc.rpc}/consensus_state`" target="_blank")
    tm-list-item(dt='Prevote State' :dd='prevotes')
    tm-list-item(dt='Precommit State' :dd='precommits')
    tm-list-item(dt='Total Transactions' :dd='num.prettyInt(totalTxs)')

  tm-part(title='Current Block' v-if="latestBlock.height > 0")
    tm-list-item(dt='Block Height' :dd='num.prettyInt(latestBlock.height)'
      :to="{ name: 'block', params: { block: latestBlock.height }}")
    tm-list-item(dt='Block Time' :dd='readableDate(latestBlock.time)')
    tm-list-item(dt='Transactions' :dd='num.prettyInt(latestBlock.num_txs)')
    tm-list-item(dt='Last Commit Hash' :dd='latestBlock.last_commit_hash')

  tm-part(title='Current Block' v-else)
    tm-list-item(dt='Block Height' :dd='num.prettyInt(latestBlock.height)'
      :to="{ name: 'block', params: { block: latestBlock.height }}")
    tm-list-item(dt='Block Time' dd='No blocks yet')
    tm-list-item(dt='Last Commit Hash' dd='N/A')

  tm-part(title='Connected To')
    tm-list-item(dt='RPC Endpoint')
      div(slot="dd")
        tm-field.node-input(
          type="text"
          v-model="bc.rpc")

</template>

<script>
import num from "../scripts/num"
import { mapGetters } from "vuex"
import { readableDate } from "../scripts/utils"
import votingValidators from "../scripts/votingValidators"
import { TmListItem, TmPage, TmPart, TmField } from "@tendermint/ui"

export default {
  name: "page-index",
  components: {
    TmListItem,
    TmPage,
    TmPart,
    TmField
  },
  computed: {
    ...mapGetters([
      "bc",
      "config",
      "nodes",
      "validators",
      "consensusState",
      "blocks",
      "latestBlock",
      "totalTxs",
    ]),
    validatorsActive() {
      if (this.validators && this.validators.length > 0) {
        return this.validatorCount
      }
      if (this.consensusState && this.consensusState.height_vote_set) {
        return "STALLED"
      }
      return "Loading..."
    },
    validatorCount() {
      return `${votingValidators(this.validators).length} voting / ${
        this.validators.length
      } total`
    },
    prevotes() {
      if (this.consensusState && this.consensusState.height_vote_set) {
        let prevotes = this.consensusState.height_vote_set[0].prevotes_bit_array
        let split = prevotes.split(" ")
        let onlineSteak = split[1].split("/")[0]
        let totalSteak = split[1].split("/")[1]
        let minimumSteak = Math.round(totalSteak * 0.6667)
        if (onlineSteak >= minimumSteak) {
          return `${split[3] * 100}% prevoted`
        } else {
          return `${split[3] *
            100}% prevoted (${onlineSteak}steak, need ${minimumSteak}steak)`
        }
      }
      return "Loading..."
    },
    precommits() {
      if (this.consensusState && this.consensusState.height_vote_set) {
        let precommits = this.consensusState.height_vote_set[0]
          .precommits_bit_array
        let split = precommits.split(" ")
        let onlineSteak = split[1].split("/")[0]
        let totalSteak = split[1].split("/")[1]
        let minimumSteak = Math.round(totalSteak * 0.6667)
        if (onlineSteak >= minimumSteak) {
          return `${Math.round(split[3] * 100)}% precommitted`
        } else {
          return `${Math.round(
            split[3] * 100
          )}% precommitted (${onlineSteak}steak, need ${minimumSteak}steak)`
        }
      }
      return "Loading..."
    }
  },
  data: () => ({
    num: num
  }),
  methods: {
    readableDate,
    toggleBlockchainSelect() {
      this.$store.commit(
        "SET_CONFIG_BLOCKCHAIN_SELECT",
        !this.config.blockchainSelect
      )
    }
  }
}
</script>

<style lang='stylus'>
@require '~variables'

.tm-field.node-input
  min-width 20rem
  height 2rem
  padding 0 0.5rem
  background transparent
  df()
</style>
