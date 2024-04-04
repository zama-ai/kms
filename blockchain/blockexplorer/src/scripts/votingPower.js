export default function(validator) {
  let string = ""

  let power = validator.tokens
  if (power.includes("/")) {
    let divisor = parseInt(power.split("/")[0])
    let dividend = parseInt(power.split("/")[1])
    if (!isFinite(divisor) && !isFinite(dividend)) {
      power = 1
    } else {
      power = Math.round((divisor / dividend) * 100) / 100
    }
  }
  string += power + " voting power"

  let shortOwner = validator.owner.split(1)[1]
  shortOwner = shortOwner.slice(0, 8)
  string += ` (${shortOwner})`

  return string
}
