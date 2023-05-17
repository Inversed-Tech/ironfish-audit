/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

import { Asset } from '@ironfish/rust-nodejs'
import { BurnDescription } from '../../primitives/burnDescription'
import { MintData, RawTransaction } from '../../primitives/rawTransaction'
import { Transaction } from '../../primitives/transaction'
import { Account, Wallet } from '../../wallet'
import { Blockchain } from '../../blockchain'
import { Assert } from '../../assert'
import { Note } from '../../primitives/note'
import { Note as NativeNote } from '@ironfish/rust-nodejs'
import { NoteHasher } from '../../merkletree/hasher'
import { NoteWitness, Witness } from '../../merkletree/witness'

export function isTransactionMine(transaction: Transaction, account: Account): boolean {
  for (const note of transaction.notes) {
    const receivedNote = note.decryptNoteForOwner(account.incomingViewKey)
    if (receivedNote) {
      return true
    }

    const spentNote = note.decryptNoteForSpender(account.outgoingViewKey)
    if (spentNote) {
      return true
    }
  }

  return false
}

export async function createRawTransaction(options: {
  wallet: Wallet
  from: Account
  to?: Account
  fee?: bigint
  amount?: bigint
  expiration?: number
  assetId?: Buffer
  outputs?: {
    publicAddress: string
    amount: bigint
    memo: string
    assetId: Buffer
  }[]
  mints?: MintData[]
  burns?: BurnDescription[]
}): Promise<RawTransaction> {
  const outputs = options.outputs ?? []

  if (options.to) {
    outputs.push({
      publicAddress: options.to.publicAddress,
      amount: options.amount ?? 1n,
      memo: '',
      assetId: options.assetId ?? Asset.nativeId(),
    })
  }

  return await options.wallet.createTransaction({
    account: options.from,
    outputs,
    mints: options.mints,
    burns: options.burns,
    fee: options.fee ?? 0n,
    expiration: options.expiration ?? 0,
    expirationDelta: 0,
  })
}

/**
 * Produces a transaction that has one mint and one output, no spends and no burns,
 * and zero transaction fee.
 */
export async function createPureMintTransaction(
  from: Account,
  to: Account,
  asset: Asset,
  amount: bigint,
  options: {
    expiration?: number
  } = { expiration: 0 },
): Promise<Transaction> {
  // construct raw transaction

  const raw = new RawTransaction()
    raw.expiration = options.expiration ?? 0
    raw.fee = 0n

  // add a Mint to the transaction

  raw.mints.push({
    name: asset.name().toString('utf8'),
    metadata: asset.metadata().toString('utf8'),
    value: amount,
  })

  // add an Output for the minted amount

  const outputNote = new NativeNote(
    to.publicAddress,
    amount,
    'Test note for a pure mint transaction',
    asset.id(),
    from.publicAddress,
  )

  raw.outputs.push({ note: new Note(outputNote.serialize()) })

  // create posted transaction

  const transaction = raw.post(from.spendingKey || '')

  // confirm that transaction has the desired properties

  Assert.isEqual(transaction.spends.length, 0)
  Assert.isEqual(transaction.notes.length, 1)
  Assert.isEqual(transaction.mints.length, 1)
  Assert.isEqual(transaction.burns.length, 0)
  Assert.isEqual(transaction.fee(), BigInt(0))

  return transaction
}
