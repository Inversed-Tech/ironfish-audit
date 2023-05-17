/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */
import { getTransactionSize } from '../network/utils/serializers'
import {
  createNodeTest,
  useAccountFixture,
  useMinerBlockFixture,
  useTxFixture,
  usePostTxFixture,
} from '../testUtilities'
import {
  createInlineDoubleSpendTransaction,
} from '../testUtilities/helpers/transaction'
import { MINED_RESULT } from './manager'
import { BlockTemplateSerde } from '../serde/BlockTemplateSerde'
import { Assert } from '../assert'
import { Asset } from '@ironfish/rust-nodejs'

describe('Mining manager', () => {
  const nodeTest = createNodeTest()

  it('should not add expired transaction to block', async () => {
    const { node, chain, wallet } = nodeTest
    const { miningManager } = node

    // Create an account with some money
    const account = await useAccountFixture(wallet)
    const block1 = await useMinerBlockFixture(chain, undefined, account, wallet)
    await expect(chain).toAddBlock(block1)
    await wallet.updateHead()

    const transaction = await useTxFixture(
      wallet,
      account,
      account,
      undefined,
      undefined,
      chain.head.sequence + 2,
    )

    jest.spyOn(node.memPool, 'orderedTransactions').mockImplementation(function* () {
      yield transaction
    })

    let results = (await miningManager.getNewBlockTransactions(chain.head.sequence + 1, 0))
      .blockTransactions
    expect(results).toHaveLength(1)
    expect(results[0].unsignedHash().equals(transaction.unsignedHash())).toBe(true)

    // It shouldn't be returned after 1 more block is added
    const block2 = await useMinerBlockFixture(chain)
    await expect(chain).toAddBlock(block2)

    results = (await miningManager.getNewBlockTransactions(chain.head.sequence + 1, 0))
      .blockTransactions
    expect(results).toHaveLength(0)
  })

  it('should stop adding transactions before block size exceeds maxBlockSizeBytes', async () => {
    const { node, chain, wallet } = nodeTest
    const { miningManager } = node

    // Create an account with some money
    const account = await useAccountFixture(wallet)
    const block1 = await useMinerBlockFixture(chain, undefined, account, wallet)
    await expect(chain).toAddBlock(block1)
    await wallet.updateHead()

    const transaction = await useTxFixture(
      wallet,
      account,
      account,
      undefined,
      undefined,
      chain.head.sequence + 2,
    )

    node.memPool.acceptTransaction(transaction)
    chain.consensus.parameters.maxBlockSizeBytes = 0

    let results = (await miningManager.getNewBlockTransactions(chain.head.sequence + 1, 0))
      .blockTransactions
    expect(results).toHaveLength(0)

    // Expand max block size, should allow transaction to be added to block
    chain.consensus.parameters.maxBlockSizeBytes = getTransactionSize(transaction)

    results = (await miningManager.getNewBlockTransactions(chain.head.sequence + 1, 0))
      .blockTransactions
    expect(results).toHaveLength(1)
    expect(results[0].hash().compare(transaction.hash())).toBe(0)
  })

  /**
   * The following test verifies that a node may incorporate an invalid
   * transaction from its mempool into a miner block template.  In this case,
   * the invalid transaction has an "inline double-spend", meaning it tries
   * to spend the same note twice in the same transaction.
   */
  it('does (!) add invalid transactions from mempool into block template', async () => {
    const { chain, node, wallet } = nodeTest
    const { miningManager, memPool } = node

    // set up a default account to enable mining

    await nodeTest.node.wallet.createAccount('account', true)

    // create an account with some money

    const account = await useAccountFixture(wallet)
    const block1 = await useMinerBlockFixture(chain, undefined, account, wallet)
    await expect(chain).toAddBlock(block1)
    await wallet.updateHead()

    // construct a block template with a bad transaction from the memory pool

    const transaction = await createInlineDoubleSpendTransaction(account, account, chain)
    memPool.acceptTransaction(transaction)
    const blockTemplate2 = await miningManager.createNewBlockTemplate(block1)

    // confirm the block template contains the bad transaction

    const block2 = BlockTemplateSerde.deserialize(blockTemplate2)
    Assert.isTrue(block2.transactions.length == 2)
    Assert.isTrue(block2.transactions[1].equals(transaction))
  })

  /**
   * The following test confirms that a node will not submit an invalid block
   * template to miners.  In particular, the node attempts to add the
   * proposed block to the chain before submitting the block for PoW mining,
   * so the exact same verification procedure is run on the template
   * (except the comparison of the block hash to the target difficulty) to
   * confirm that the resulting mined block will be accepted by consensus
   * rules.
   * 
   * In this test, a block template is produced containing an inline
   * double-spend transaction, which tries to spend the same note twice in
   * the same transaction.  The block template with this transaction is
   * produced by the node, but then is blocked before being submitted to the
   * miner RPC.
   */
  it('does not submit invalid block templates to miners', async () => {
    const { chain, node, wallet } = nodeTest
    const { miningManager, memPool } = node

    // set up a default account to enable mining

    await nodeTest.node.wallet.createAccount('account', true)

    // create an account with some money

    const account = await useAccountFixture(wallet)
    const block1 = await useMinerBlockFixture(chain, undefined, account, wallet)
    await expect(chain).toAddBlock(block1)
    await wallet.updateHead()

    // construct a block template with a bad transaction from the memory pool

    const transaction = await createInlineDoubleSpendTransaction(account, account, chain)
    memPool.acceptTransaction(transaction)
    const blockTemplate2 = await miningManager.createNewBlockTemplate(block1)

    // attempt to submit block template to the miner RPC

    await expect(miningManager.submitBlockTemplate(blockTemplate2)).resolves.toBe(
      MINED_RESULT.ADD_FAILED
    )
  })
})
