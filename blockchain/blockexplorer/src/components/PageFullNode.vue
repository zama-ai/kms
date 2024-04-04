<template lang="pug">
tm-page(:title="`Node: ${getIp(fullNode)}`")
  div(slot="menu"): tm-tool-bar
    router-link(to="/nodes" exact): i.material-icons arrow_back
    anchor-copy(:value="persistentPeer" icon="content_copy")

  tm-part(title='ID')
    tm-list-item(dt="Moniker" :dd="fullNode.node_info.moniker")
    tm-list-item(dt="IP" :dd="getIp(fullNode)")
    tm-list-item(dt="Start Date" :dd="fullNode.connection_status && readableDate(fullNode.connection_status.SendMonitor.Start)")

  tm-part(title='Pub Key')
    tm-list-item(dt="Value" :dd="fullNode.node_info.id")
    tm-list-item(dt="Persistent Peer" :dd="persistentPeer")

  tm-part(title='Network')
    tm-list-item(dt="Network" :dd="fullNode.node_info.network")
    tm-list-item(dt="Tendermint Version" :dd="fullNode.node_info.version")
    tm-list-item(dt="Channels" :dd="fullNode.node_info.channels")

  // tm-part(title='Profile')
    tm-list-item(dt="Total Vote Power" :dd="fullNode.fullNode ? fullNode.fullNode.voting_power : 0 + ' ATOM'" to="/vote-power")
    //tm-list-item(dt="Solo Vote Power" dd="1M ATOM (19%)")
    //tm-list-item(dt="Delg. Vote Power" dd="3.2M ATOM (81%)")
    //tm-list-item(dt="Vote History" dd="37 Votes" to="/votes")
    //tm-list-item(dt="Proposals" dd="13" to="/proposals")
    //tm-list-item(dt="Slashes" dd="6" to="/slashes")

  //tm-part(title='Staking')
    tm-list-item(dt="Delegators" dd="" to="/delegators")
    tm-list-item(dt="Earn Rate" dd="8.1K ATOM / day'")
    tm-list-item(dt="Total Earnings" dd="301.8K ATOM")
</template>

<script>
import { mapGetters } from "vuex"
import { readableDate } from "../scripts/utils"
import { TmListItem, TmPage, TmPart, TmToolBar } from "@tendermint/ui"
import AnchorCopy from "./AnchorCopy"

export default {
  name: "page-fullNode",
  components: {
    AnchorCopy,
    TmListItem,
    TmPage,
    TmPart,
    TmToolBar
  },
  computed: {
    ...mapGetters(["nodes"]),
    fullNode() {
      if (this.nodes && this.nodes.length > 0) {
        return this.nodes.find(
          v =>
            this.urlsafeIp(v.node_info.listen_addr) ===
            this.$route.params.node + ":26656"
        )
      } else {
        return this.tmpFullNode
      }
    },
    persistentPeer() {
      return `${this.fullNode.node_info.id}@${
        this.fullNode.node_info.listen_addr
      }`
    }
  },
  data: () => ({
    tmpFullNode: {
      node_info: {
        moniker: "Loading...",
        pub_key: "todoreplacemewithfullNodepubkey"
      }
    }
  }),
  methods: {
    urlsafeIp(ip) {
      return ip.split(".").join("-")
    },
    getIp(fullNode) {
      return (
        fullNode.node_info.listen_addr &&
        fullNode.node_info.listen_addr.split(":")[0]
      )
    },
    readableDate
  },
  mounted() {
    // setInterval(console.log(this.fullNode), 1000)
  }
}
</script>
