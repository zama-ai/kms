import { orderBy } from "lodash"
export default function(validators) {
  let orderedValidators = validators
  if (validators && validators.length > 1) {
    orderedValidators = orderBy(
      validators,
      [i => {
        if (i.description && i.description.moniker) {
          return i.description.moniker.toLowerCase()
        } else {
          return i.address
        }
      }],
      ["asc"]
    )
  }
  return orderedValidators
}
