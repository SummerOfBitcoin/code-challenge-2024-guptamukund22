# Design Approach
In order to create valid block, I first had to find out the what all transactions were valid..This included unlocking the scripts(pubkey) using sigscripts, especially checking whether the signatures matched for the particular public key. It also included verifying the address from the public key, checking whether the amount imput is greater than output and that no transaction is repeated. Once they were verified, I put the set of transactions that were valid in another json file (valid-cache) according to their transaction fee as going through each file again and again would increase the time for making the block.(This step was only done to fasten the mining process).

Now, I serialized the transaction and double hashed them , and reversed them to form the transcation id. This step was accompanied with also giving the witness transaction ids for forming the coinbase transaction. Once this was done, I moved on to create the coinbase transaction. 

This step included forming the witness commitment from the merkel root of the witness transaction and then double SHA 256 of the witness reserved value and witness commitment. After other appropriate fields like version, flags, script, amount, etc were added, I created the coinbase transaction id.

Once this was done, I created the merkel root of transaction ids(including the coinbase), included important fields like version, bits , etc, in the block header and tried to form a proof of work. Once this was done, I simply put the block header along with number of transaction along wth their transaction ids in output.txt. This formed my Block.

# Implementation Detail
Here is a pseudo code on how I performed it: 

```python
# This returned the list of valid transactions for each kind of transaction for eg: p2sh, p2pkh etc.
transactions = process_mempool()

# This function returns the max amount that I can extract given the block size constraint along with serialize transaction
best_transaction, amount = best_transactions_for_block(transactions)

# Convert amount to little endian hex format
amount = amount.to_bytes(8, byteorder='little').hex()

# This function returned the txn ids for merkle root and wtxid ids for coinbase txn
tx_id, wid = return_id(best_transaction)

# Forming of coinbase transaction based on wtxn id and amount generated
coinbase_txn, coinbase_id = coinbase(wid, amount)

# Inserting the coinbase as first transaction in block
tx_id.insert(0, coinbase_id)

# Finding the merkle root out of it
root = merkle_root(tx_id)

# Creating the block header after providing the proof of work
block_header = create_block_header(root)
```

# Results and Performance
The code took only 90 secs to execute and I was able to get a score of 98/100 for it.

# Conclusion
The assignment helped in learing the basic intricacies of bitcoin and how transactions are validated to form a block. I belive that p2tr transaction should have been included as well to teach more about bitcoin and blockchain.

Resources I used typically included :
[learnmeabitcoin](https://learnmeabitcoin.com/)
[Mastering Bitcoin](https://github.com/bitcoinbook/bitcoinbook)

