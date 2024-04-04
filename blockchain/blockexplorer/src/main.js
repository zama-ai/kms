import Vue from "vue"
import App from "./app"
import Vuelidate from "vuelidate"
import VueAnalytics from "vue-analytics"

// sync store and router...
import { sync } from "vuex-router-sync"
import store from "./store/index.js"
import router from "./router/index.js"
sync(store, router)

Vue.use(Vuelidate)
Vue.use(VueAnalytics, { id: "UA-51029217-4", router: router })
Vue.config.productionTip = false

/* eslint-disable no-new */
new Vue({
  el: "#app",
  router,
  render: h => h(App),
  store
})
