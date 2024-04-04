<template lang="pug">
tm-page(title='Search')
  tm-part(title='Search')
    tm-form-struct(:submit="search")
      tm-form-group
        .tm-modal-search
          tm-field#search-input(
            type="text"
            placeholder="Search for block"
            required
            v-model="query"
            pattern=".{1,60}"
            title="1 to 60 characters")
          tm-btn(type="submit" icon="search" value="Go")

  tm-part(title='Sample Queries')
    // tm-list-item(dt='Address' dd='3HNSiAq7wFDaPsYDcUxNSRMD78qVcYKicw' @click.native="fillField('3HNSiAq7wFDaPsYDcUxNSRMD78qVcYKicw')")
    // tm-list-item(dt='Transaction' dd='878797d16182f6ffa5e98cd88576ab973b8d6f9dfe8ff441bd3521a7d8559800' @click.native="fillField('878797d16182f6ffa5e98cd88576ab973b8d6f9dfe8ff441bd3521a7d8559800')")
    tm-list-item(dt='Block #' dd='1337' @click.native="fillField('1337')")
</template>

<script>
import { mapGetters } from "vuex"
import {
  TmListItem,
  TmFormGroup,
  TmFormStruct,
  TmPage,
  TmPart,
  TmBtn,
  TmField
} from "@tendermint/ui"
export default {
  name: "page-search",
  components: {
    TmBtn,
    TmField,
    TmFormGroup,
    TmFormStruct,
    TmListItem,
    TmPage,
    TmPart
  },
  computed: {
    ...mapGetters(["bc"])
  },
  data: () => ({
    query: ""
  }),
  methods: {
    fillField(value) {
      this.query = value
    },
    search() {
      if (parseInt(this.query)) {
        this.$router.push({ name: "block", params: { block: this.query } })
      } else {
        console.log("Only block # queries are supported right now", this.query)
      }
    }
  }
}
</script>
<style lang="stylus">
.tm-modal-search
  display: flex;
  flex: 1;
  .tm-field
    width: auto;
    flex: 1;
  .tm-btn
    margin-left: 0.5rem;
</style>
