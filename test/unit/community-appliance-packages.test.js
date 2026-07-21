import test from 'brittle'
import { validateCommunityAppliancePackages } from '../../scripts/check-community-appliance-packages.mjs'

test('community appliance package bundle validates', (t) => {
  const result = validateCommunityAppliancePackages()
  t.comment(result.errors.join('\n'))
  t.ok(result.ok, 'all community appliance packages validate')
  t.alike(result.packages, ['unraid', 'zimaos-casaos', 'runtipi', 'hexos'])
})
