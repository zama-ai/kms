import moment from "moment"

export const readableDate = ms => {
  return moment(ms).format("YYYY-MM-DD hh:mm:ss")
}
