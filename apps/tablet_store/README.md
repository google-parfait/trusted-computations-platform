# Trusted Tablet Store Application

Tablet Store is a replicated rollback protected computation running on top of
Trusted Computations Platform. Tablet Store represents the root of trust for
the private data that is being stored in the tablets. Therefore Tablet Store
is the provider of the chain of trust attestation and holder of the encryption
keys for the private data.

Tablet Store interface is coarse and is expressed in terms of tablets.
Tablet Store exposes essentially read (with snapshot isolation level) and
write (with serializable isolation level) transactions. Tablet Store represents
transactions as entries in the replicated log. Upon successful commitment
of the transaction entry it is evaluated and if successful applied to the
Tablet Store state.