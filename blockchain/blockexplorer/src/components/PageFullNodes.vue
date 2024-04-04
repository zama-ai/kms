<template lang="pug">
tm-page(title='Full Nodes')
  // tm-tab-bar
    router-link(to="/nodes" exact) Connected Nodes ({{ online }})
    a(@click.prevent='toggleFilter'): i.material-icons(:class="{'mdi-rotate-180': asc}") filter_list
    a(@click='toggleSearch'): i.material-icons search
  tm-list-item(
    v-for="i in orderedFullNodes"
    :key="i.node_info.listen_addr"
    :title="i.node_info.moniker"
    :subtitle="getIp(i)"
    icon='storage'
    :to="`/nodes/${urlsafeIp(getIp(i))}`")
</template>

<script>
import { mapGetters } from "vuex"
import { orderBy } from "lodash"
import { TmListItem, TmPage, TmTabBar, TmToolBar } from "@tendermint/ui"
export default {
  name: "page-nodes",
  components: {
    TmListItem,
    TmPage,
    TmTabBar,
    TmToolBar
  },
  data() {
    return {
      asc: true
    }
  },
  computed: {
    ...mapGetters(["nodes"]),
    orderedFullNodes() {
      if (this.nodes) {
        return orderBy(
          this.nodes,
          [n => n.node_info.moniker.toLowerCase()],
          this.asc ? "asc" : "desc"
        )
      } else {
        return []
      }
    }
  },
  methods: {
    toggleFilter() {
      this.asc = !this.asc
      // this.$store.commit('notify', { title: 'Filtering...', body: 'TODO' })
    },
    toggleSearch() {
      // this.$store.commit('notify', { title: 'Searching...', body: 'TODO' })
    },
    urlsafeIp(ip) {
      return ip && ip.split(".").join("-")
    },
    getIp(fullNode) {
      return (
        fullNode.node_info.listen_addr &&
        fullNode.node_info.listen_addr.split(":")[0]
      )
    }
  }
}
</script>
