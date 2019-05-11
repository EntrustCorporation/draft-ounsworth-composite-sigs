# Reference implementation in Go / CFSSL

## verification_policy.json
This file implements a sample client-side policy for deciding which algoritm(s) are acceptable. This is meant to be informative and provide ideas for how one might implement such a policy.

`policyType` is one of:

  - `oneIsTrusted`: The signature contains at least one valid component signature using an algorithm listed in `knownAlgs`.

  - `groupCombinationisTrusted`: The signature contains component signature(s) that form a superset of one of the combinations of alg groups listed in `trustedGroupCombinations`. _We note that this method gives less control than the `algCombinationIsTrusted`, but will scale better with a large number of supported algorithms._

  - `algCombinationIsTrusted`: The signature contains component signature(s) that form a superset of one of the combinations of algs listed in `trustedAlgCombinations`. _We note that this method will get unwieldy if the client has a large number of supported algorithms and permutations._
