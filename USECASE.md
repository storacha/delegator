# How WSP’s Join the Staging Network

1. A WSP Operator will follow the directions [here](https://www.notion.so/How-to-Run-a-Storacha-Warm-Storage-Node-with-Curio-1de5305b552480a5a8dacc684f6ef964?pvs=21) to setup a Storacha Warm Storage Node. Through following this doc the WSP Operator will create:
    1. A **DID** for their warm storage node
    2. A **FQDN** their warm storage node is reachable at
    3. A **Filecoin Address** they will use to send messages to the PDP Smart Contract.
    4. A **Proof Set** on the PDP contract will prove over.
2. The WSP will communicate their **DID** to the Storacha Team privately (telegram, discord, signal, carrier-pigeon, etc.).
    1. The Storacha Team will allow-list the WSP’s **DID** on the Delegator.
3. The WSP will visit [`delegator.staging.warm.storacha.network`](http://delegator.staging.warm.storacha.network).
    1. The delegator will prompt the WSP Operator for the **DID** of their node.
    2. The WSP Operator will enter their **DID**
        1. The delegator will assert the **DID** is in its allowlist and isn’t already registered.
        2. The delegator will generate a delegation/proof for the WSP to access the indexer.
        3. The WSP will be prompted to download the delegation/proof
        4. The WSP will be provided instruction on how to configure their Piri node to use the delegation/proof they downloaded.
        5. The WSP will start their piri node with the delegation/proof attached.
    3. The delegator will prompt the WSP Operator for the **FQDN** their Piri node is serving on.
        1. The delegator will dial the piri node at the **FQDN** and assert it returns the **DID** the WSP Operator provided. (a psudo-verification and readiness-check)
        2. The delegator will tell the WSP Operator to generate a delegation on their storage node that allows the upload service to issue delegations for storing data. The WSP Operator will be prompted to enter the delegation/proof in the form.
        3. Upon a successful dial/verification, the delegator will add an entry to the *staging-warm-w3infra-storage-provider* ****dynamoDB table. The following fields will be populated in the table:
            1. Provider: WSP **DID**
            2. Endpoint: **FQDN** of WSP
            3. Proof:  from step above
            4. Weight: ??
            5. InsertedAt: time.Now()
            6. UpdatedAt: time.Now()
    4. The delegator will prompt the WSP Operator for the **Filecoin Address** and **Proof Set** they will be using for submitting messages to the PDP Smart Contract.
        1. The delegator will record this information in a *staging-warm-w3infra-storage-provider-info* dynamoDB table with the following fields:
            1. Provider: WSP **DID**
            2. Endpoint: WSP **FQND**
            3. Address: WSP **Filecoin Address**
            4. Proof Set: WSP **Proof Set**
            5. Operator Email
    5. The delegator will notify the WSP Operator that setup is complete, and that they will begin receiving warm storage deals.