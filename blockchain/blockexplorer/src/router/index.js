import Vue from "vue"
import Router from "vue-router"

Vue.use(Router)

import Index from "../components/PageIndex"
import Search from "../components/PageSearch"
import Blocks from "../components/PageBlocks"
import Block from "../components/PageBlock"
import Tx from "../components/PageTx"
import FullNodes from "../components/PageFullNodes"
import FullNode from "../components/PageFullNode"
import PageValidators from "../components/PageValidators"
import PageValidatorsIndex from "../components/PageValidatorsIndex"
import PageValidatorsRevoked from "../components/PageValidatorsRevoked"
import PageValidator from "../components/PageValidator"

const routes = [
  { path: "/", component: Index },
  { path: "/search", component: Search },
  { path: "/blocks", component: Blocks },
  { path: "/blocks/:block", name: "block", component: Block },
  { path: "/tx/:hash", name: "tx", component: Tx }, // TODO rename path to /txs
  { path: "/nodes", component: FullNodes },
  {
    name: "node",
    path: "/nodes/:node",
    component: FullNode
  },

  // VALIDATORS
  {
    path: "/validators",
    component: PageValidators,
    children: [
      {
        path: "/",
        name: "validators",
        component: PageValidatorsIndex
      },
      {
        path: ":validator",
        name: "validator",
        component: PageValidator
      }
    ]
  },

  // REVOKED
  {
    path: "/validators-revoked",
    name: "validators-revoked",
    component: PageValidatorsRevoked
  }
]

export default new Router({
  mode: "history",
  routes: routes,
  scrollBehavior(to, from) {
    if (to.hash && to.hash.length > 0) {
      return {
        selector: to.hash
      }
    }
    return { x: 0, y: 0 }
  }
})
