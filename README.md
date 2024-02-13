# A Prototype Vault using CAT

## Operations
### Deposit

Send to the contract

### Trigger Withdrawal 
- Inputs
  1. contract input
  2. fee-paying input
- Outputs
  1. Contract output with amount to be withdrawn
  2. Target address with dust amount
### Complete Withdrawal
- Inputs
  1. Withdrawal input
    - Second output of the previous transaction must be dust. The address will be used to validate the withdrawal destination
  2. Fee-paying input
- Outputs
  1. Destination output, with the amount to be withdrawn checked by the contract and the scriptpubkey checked by the contract
  2. fee-change output

### Cancel Withdrawal
- Inputs
  1. Any contract input
  2. Fee-paying input
- Outputs
  1. Contract output  

## TODO
