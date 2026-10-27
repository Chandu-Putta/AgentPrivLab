# Run summary (auto-generated from CSVs; do not edit)

- seed: 42, scenarios: 35 templates / 156 instances, action rows (all conditions): 5008
- python 3.12.15, mcp 1.30.0, platform macOS-26.5.1-arm64-arm-64bit
- LABELS: deterministic = scripted traces measuring *enforcement*, not LLM susceptibility; approval simulation = synthetic reviewer model; timing = this machine only.
- CAVEAT: instances of one scenario template are near-duplicates (account/tenant permutations), so Wilson intervals treat correlated trials as independent and are optimistic. Percentages depend on the scenario mix and are not attack-prevalence estimates.

## Security and usability (primary condition, common scenarios; % (k/n) [95% Wilson CI])

| strategy | unauthorized exec | authorized not executed | legit task completion | delegation expansion rejected |
|---|---|---|---|---|
| broad_role | 76.9% (80/104) [68.0, 84.0] | 0.0% (0/104) [0.0, 3.6] | 100.0% (52/52) [93.1, 100.0] | 0.0% (0/12) [0.0, 24.3] |
| restricted_role | 34.6% (36/104) [26.2, 44.2] | 3.8% (4/104) [1.5, 9.5] | 92.3% (48/52) [81.8, 97.0] | 0.0% (0/12) [0.0, 24.3] |
| session_scope | 26.9% (28/104) [19.3, 36.2] | 3.8% (4/104) [1.5, 9.5] | 92.3% (48/52) [81.8, 97.0] | 0.0% (0/12) [0.0, 24.3] |
| task_capability | 11.5% (12/104) [6.7, 19.1] | 0.0% (0/104) [0.0, 3.6] | 100.0% (52/52) [93.1, 100.0] | 0.0% (0/12) [0.0, 24.3] |
| external_policy | 11.5% (12/104) [6.7, 19.1] | 0.0% (0/104) [0.0, 3.6] | 100.0% (52/52) [93.1, 100.0] | 0.0% (0/12) [0.0, 24.3] |
| policy_plus_approval | 7.7% (8/104) [3.9, 14.4] | 0.0% (0/104) [0.0, 3.6] | 100.0% (52/52) [93.1, 100.0] | 0.0% (0/12) [0.0, 24.3] |
| delegated_attenuation | 7.7% (8/104) [3.9, 14.4] | 0.0% (0/104) [0.0, 3.6] | 100.0% (52/52) [93.1, 100.0] | 100.0% (12/12) [75.7, 100.0] |
| delegated_naive | 11.5% (12/104) [6.7, 19.1] | 0.0% (0/104) [0.0, 3.6] | 100.0% (52/52) [93.1, 100.0] | 0.0% (0/12) [0.0, 24.3] |
| external_policy_failopen | 11.5% (12/104) [6.7, 19.1] | 0.0% (0/104) [0.0, 3.6] | 100.0% (52/52) [93.1, 100.0] | 0.0% (0/12) [0.0, 24.3] |
| direct_no_gateway | 76.9% (80/104) [68.0, 84.0] | 0.0% (0/104) [0.0, 3.6] | 100.0% (52/52) [93.1, 100.0] | 0.0% (0/12) [0.0, 24.3] |

## Targeted scenarios (apply to a subset of strategies)

| strategy | unauthorized exec (targeted) | authorized not executed (targeted) |
|---|---|---|
| task_capability | 0.0% (0/4) [0.0, 49.0] | n/a |
| external_policy | 0.0% (0/4) [0.0, 49.0] | 100.0% (4/4) [51.0, 100.0] |
| policy_plus_approval | 0.0% (0/16) [0.0, 19.4] | 50.0% (4/8) [21.5, 78.5] |
| delegated_attenuation | 0.0% (0/4) [0.0, 49.0] | 100.0% (4/4) [51.0, 100.0] |
| delegated_naive | 0.0% (0/4) [0.0, 49.0] | 100.0% (4/4) [51.0, 100.0] |
| external_policy_failopen | 100.0% (4/4) [51.0, 100.0] | 0.0% (0/4) [0.0, 49.0] |

## Layered condition (backend independently enforces tenant/account/limit claims)

| strategy | unauthorized exec (gateway-only) | unauthorized exec (gateway + backend) |
|---|---|---|
| broad_role | 76.9% (80/104) [68.0, 84.0] | 63.5% (66/104) [53.9, 72.1] |
| restricted_role | 34.6% (36/104) [26.2, 44.2] | 34.6% (36/104) [26.2, 44.2] |
| session_scope | 26.9% (28/104) [19.3, 36.2] | 26.9% (28/104) [19.3, 36.2] |
| task_capability | 11.5% (12/104) [6.7, 19.1] | 11.5% (12/104) [6.7, 19.1] |
| external_policy | 11.5% (12/104) [6.7, 19.1] | 11.5% (12/104) [6.7, 19.1] |
| policy_plus_approval | 7.7% (8/104) [3.9, 14.4] | 7.7% (8/104) [3.9, 14.4] |
| delegated_attenuation | 7.7% (8/104) [3.9, 14.4] | 7.7% (8/104) [3.9, 14.4] |
| delegated_naive | 11.5% (12/104) [6.7, 19.1] | 11.5% (12/104) [6.7, 19.1] |
| external_policy_failopen | 11.5% (12/104) [6.7, 19.1] | 11.5% (12/104) [6.7, 19.1] |
| direct_no_gateway | 76.9% (80/104) [68.0, 84.0] | 67.3% (70/104) [57.8, 75.6] |

## Reviewer sensitivity for policy_plus_approval (common scenarios)

| condition | unauthorized exec | authorized not executed |
|---|---|---|
| primary | 7.7% (8/104) [3.9, 14.4] | 0.0% (0/104) [0.0, 3.6] |
| rubber_stamp | 11.5% (12/104) [6.7, 19.1] | 0.0% (0/104) [0.0, 3.6] |
| always_reject | 7.7% (8/104) [3.9, 14.4] | 15.4% (16/104) [9.7, 23.5] |

## Paired comparisons on shared unauthorized proposals (exact McNemar on discordant pairs)

| A | B | pairs | A executed | B executed | A only | B only | p |
|---|---|---|---|---|---|---|---|
| broad_role | restricted_role | 104 | 80 | 36 | 44 | 0 | 1.1e-13 |
| restricted_role | task_capability | 104 | 36 | 12 | 28 | 4 | 1.9e-05 |
| restricted_role | external_policy | 104 | 36 | 12 | 28 | 4 | 1.9e-05 |
| session_scope | external_policy | 104 | 28 | 12 | 20 | 4 | 0.0015 |
| task_capability | external_policy | 104 | 12 | 12 | 0 | 0 | 1 |
| external_policy | policy_plus_approval | 104 | 12 | 8 | 4 | 0 | 0.12 |
| external_policy | delegated_attenuation | 104 | 12 | 8 | 4 | 0 | 0.12 |
| delegated_naive | delegated_attenuation | 104 | 12 | 8 | 4 | 0 | 0.12 |

## Audit replay

```json
{
 "total": 2048,
 "reproduced": 2048,
 "reconstructability": 1.0,
 "chain_breaks": 0,
 "incomplete": 0,
 "mismatches": 0,
 "unparseable": 0,
 "ok": true
}
```

## Seed stability (differing action outcomes vs primary seed)

- seed 1: 0 of 2260 differ
- seed 2: 0 of 2260 differ

Figures: `figures/`. Raw data: `deterministic/*.csv`, `performance/*.csv`, `approval-simulation/sweep.csv`.
