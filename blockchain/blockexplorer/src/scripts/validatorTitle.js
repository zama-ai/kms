export default function(validator) {
  let title
  if (validator.description && validator.description.moniker) {
    title = validator.description.moniker
  } else {
    title = "Anonymous"
  }
  return title
}
