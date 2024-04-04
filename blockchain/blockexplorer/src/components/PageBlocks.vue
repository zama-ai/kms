<template lang="pug">
tm-page(title='Blocks')
  div(slot="menu"): tm-tool-bar
    router-link(:to="{ path: '/blocks', query: prevQuery }" v-if="hasPrevPage")
      i.material-icons chevron_left
      | Prev. blocks
    router-link(:to="{ path: '/blocks', query: nextQuery }" v-if="hasNextPage")
      | Next blocks
      i.material-icons chevron_right
    a(:href="jsonUrl" target="_blank") JSON

  table.BlocksTable
    thead
      th Height
      th Txs
      th Time
      th Last Commit Hash
    tbody
      tr(v-for="x in blocks" :key="x.header.height")
        td
          router-link(:to="`/blocks/${x.header.height}`")
            | {{ num.prettyInt(x.header.height) }}
        td(:class="{ noTxs: parseInt(x.header.num_txs) === 0 }") {{ num.prettyInt(x.header.num_txs) }}
        td {{ readableDate(x.header.time) }}
        td {{ x.header.last_commit_hash }}
</template>

<script>
import axios from "axios"
import moment from "moment"
import num from "../scripts/num"

import { mapGetters } from "vuex"
import { readableDate } from "../scripts/utils"
import { TmListItem, TmPage, TmTabBar, TmToolBar } from "@tendermint/ui"

// Tendermint REST RPC doesn't return more than 20 blocks per request.
const maxItemsPerPage = 20

export default {
  name: "page-blocks",
  components: {
    TmListItem,
    TmPage,
    TmTabBar,
    TmToolBar
  },
  data() {
    return {
      moment: moment,
      num: num,
      jsonUrl: "",
      itemsPerPage: maxItemsPerPage,
      minHeight: 0,
      maxHeight: 0,
      blocks: []
    }
  },
  computed: {
    ...mapGetters([
      "blockchain",
      "totalBlocks",
    ]),
    hasPrevPage() {
      return this.totalBlocks > 0 && this.minHeight > 1
    },
    hasNextPage() {
      return this.totalBlocks > 0 && this.maxHeight < this.totalBlocks
    },
    prevQuery() {
      if (!this.hasPrevPage) return {}

      let { itemsPerPage, minHeight, maxHeight } = this
      return {
        minHeight: minHeight - itemsPerPage,
        maxHeight: maxHeight - itemsPerPage
      }
    },
    nextQuery() {
      if (!this.hasNextPage) return {}

      let { itemsPerPage, minHeight, maxHeight } = this
      return {
        minHeight: minHeight + itemsPerPage,
        maxHeight: maxHeight + itemsPerPage
      }
    },
  },
  methods: {
    readableDate,
    async fetchPageOfBlocks() {
      let { totalBlocks, itemsPerPage } = this

      let { minHeight, maxHeight } = this.$route.query
      if (minHeight) minHeight = parseInt(minHeight)
      if (maxHeight) maxHeight = parseInt(maxHeight)

      if (totalBlocks > 0 && (!maxHeight || maxHeight < 1 || maxHeight > totalBlocks)) {
        maxHeight = totalBlocks
      }
      if (!minHeight && maxHeight) {
        minHeight = maxHeight - itemsPerPage + 1
      }
      if (minHeight < 1) {
        minHeight = 1
      }

      let query = (minHeight || maxHeight) ? `?minHeight=${minHeight}&maxHeight=${maxHeight}` : ''
      this.jsonUrl = `${this.blockchain.rpc}/blockchain${query}`
      let json = await axios.get(this.jsonUrl)
      this.blocks = json.data.result.block_metas

      minHeight = 0
      maxHeight = 0
      this.blocks.forEach(block => {
        let height = parseInt(block.header.height)
        if (height < minHeight || !minHeight) minHeight = height
        if (height > maxHeight || !maxHeight) maxHeight = height
      })
      this.minHeight = minHeight
      this.maxHeight = maxHeight
    },
  },
  async mounted() {
    await this.fetchPageOfBlocks()
  },
  watch: {
    '$route'() {
      this.fetchPageOfBlocks()
    }
  }
}
</script>

<style lang="stylus">
.BlocksTable
  width 100%
  th
    font-weight bold
    color var(--dim)
    background var(--app-fg)
  tr
    &:hover
      background-color var(--hover-bg)
  th
  td
    border-bottom 0.125rem solid var(--bc-dim)
    padding 0.5rem 1rem

    &.noTxs
      color var(--dim)
      font-weight normal
</style>
