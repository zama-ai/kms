<template lang="pug">
tm-page(:title="`Block ${block.header.height}${hasNextBlock ? '' : ' (the latest block)'}`")
  div(slot="menu"): tm-tool-bar
    router-link(:to="{ name: 'block', params: { block: prevHeight }}" v-if="hasPrevBlock")
      i.material-icons chevron_left
      | Block {{ prevHeight }}
    router-link(:to="{ name: 'block', params: { block: nextHeight }}" v-if="hasNextBlock")
      | Block {{ nextHeight }}
      i.material-icons chevron_right
    a(:href="jsonUrl" target="_blank") JSON

  div(v-if="block.data.txs.length > 0")
    part-tx-data(
      v-for="(x, i) in decodedTxs"
      :data="x"
      :name="`Transaction ${i+1} / ${decodedTxs.length}`"
      :path-prefix="`tx.${i}.`"
      :includeFields="[]"
      :excludeFields="[]"
      v-bind:key="i"
    )
  tm-part(v-else title="This block has no transactions")

  tm-part(title='Block Header')
    tm-list-item(dt="Chain ID" :dd="block.header.chain_id")
    tm-list-item(dt="Time" :dd="block.header.time")
    tm-list-item(dt="Transactions" :dd="block.data.txs.length")
    tm-list-item(dt="Last Commit Hash" :dd="block.header.last_commit_hash")
    tm-list-item(dt="Validators Hash" :dd="block.header.validators_hash")
    tm-list-item(dt="App Hash" :dd="block.header.app_hash")

  tm-part(title='Last Block')
    tm-list-item(dt="Hash" :dd="block.header.last_block_id.hash")
    tm-list-item(dt="Parts Total" :dd="block.header.last_block_id.parts.total")
    tm-list-item(dt="Parts Hash" :dd="block.header.last_block_id.parts.hash")

  tm-part(title="Precommit"
    v-for="p in block.last_commit.precommits"
    :key="p.validator_address" v-if="p !== null")
    tm-list-item(dt="Address" :dd="p.validator_address")
    tm-list-item(dt="Index" :dd="p.validator_index")
    tm-list-item(dt="Round" :dd="p.round")
    tm-list-item(:dt="`Sig (${p.signature.type})`"
    :dd="p.signature.data")
</template>

<script>
import { mapGetters } from "vuex"
import axios from "axios"
import createHash from "create-hash"
import varint from "varint"
import b64 from "base64-js"
import { decodeBase64, decodeTx } from "../scripts/tx"
import PartTxData from './PartTxData'
import { TmListItem, TmPage, TmPart, TmToolBar } from "@tendermint/ui"

export default {
  name: "page-block",
  components: {
    TmToolBar,
    TmListItem,
    TmPart,
    TmPage,
    PartTxData
  },
  computed: {
    ...mapGetters([
      "blockchain",
      "totalBlocks"
    ]),
    prevHeight() {
      return this.block.header.height - 1
    },
    nextHeight() {
      return this.block.header.height + 1
    },
    hasPrevBlock() {
      return this.prevHeight > 0
    },
    hasNextBlock() {
      return this.nextHeight <= this.totalBlocks
    },
    decodedTxs () {
      return this.block.data.txs.map((tx, i) => {
        let txObj = {
          data: decodeTx(tx)
        }
        let hash = this.txHash(i)
        let txHash = {
          isRouterLink: true,
          title: "View transaction details",
          text: hash,
          to: { name: "tx", params: { hash } }
        }
        return Object.assign({ txHash }, txObj)
      })
    },
  },
  data: () => ({
    jsonUrl: "",
    block: {
      header: {
        chain_id: "",
        height: 0,
        time: "",
        last_block_id: {
          hash: "",
          parts: {
            total: 0,
            hash: ""
          }
        },
        last_commit_hash: "",
        data_hash: "",
        validators_hash: "",
        app_hash: ""
      },
      data: {
        txs: []
      },
      last_commit: {
        blockID: {
          hash: "",
          parts: {
            total: 0,
            hash: ""
          }
        },
        precommits: [
          {
            validator_address: "",
            validator_index: 0,
            height: 0,
            round: 0,
            type: 0,
            block_id: {
              hash: "",
              parts: {
                total: 0,
                hash: ""
              }
            },
            signature: [0, ""]
          }
        ]
      }
    }
  }),
  methods: {
    txHash (idx) {
      let tx = this.block.data.txs[idx]
      let b64str = tx.replace(/^:base64:/, '')
      let buffer = Buffer.from(b64str, 'base64')
      let hex = createHash('sha256').update(buffer).digest('hex')
      return hex.toUpperCase()
    },
    async fetchBlock() {
      this.jsonUrl = `${this.blockchain.rpc}/block?height=${this.$route.params.block}`
      let json = await axios.get(this.jsonUrl)
      this.block = json.data.result.block
      this.block.header.height = parseInt(this.block.header.height)
    },

    // TODO deprecate? (yes)
    queryTxs() {
      return this.queryTx(this.block.data.txs.length)
    },

    // TODO deprecate? (yes)
    queryTx(len, key = 0) {
      return new Promise((resolve, reject) => {
        if (key >= len) resolve()
        let txstring = decodeBase64(this.block.data.txs[key])
        //console.log(txstring)
        let txbytes = b64.toByteArray(this.block.data.txs[key])
        // console.log(txbytes)
        let varintlen = new Uint8Array(varint.encode(txbytes.length))
        // console.log(varintlen)
        let tmp = new Uint8Array(varintlen.byteLength + txbytes.byteLength)
        tmp.set(new Uint8Array(varintlen), 0)
        tmp.set(new Uint8Array(txbytes), varintlen.byteLength)
        // console.log(tmp)

        // TODO replace with fixed decoding that uses SHA256
        let hash = createHash("ripemd160")
          .update(Buffer.from(tmp))
          .digest("hex")
        // console.log(hash)

        let url = `${this.blockchain.rpc}/tx?hash=0x${hash}`
        axios
          .get(url)
          .then(json => {
            // console.log(json)
            json.data.result.string = txstring
            this.block.data.txs.splice(key, 1, json.data.result)
            this.queryTx(len, key + 1)
              .then(resolve)
              .catch(reject)
          })
          .catch(reject)
      })
    }
  },
  async mounted() {
    await this.fetchBlock()
  },
  watch: {
    // eslint-disable-next-line
    '$route'(to, from) {
      this.fetchBlock()
    }
  }
}
</script>
