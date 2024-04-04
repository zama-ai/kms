export default function(validators) {
  if (validators && validators.length > 0) {
    return validators.filter(v => v.revoked)
  } else {
    return []
  }
}
