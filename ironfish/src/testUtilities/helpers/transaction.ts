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
 * Return a single note from an account owned by a wallet, with positive value
 * of a specified asset.
 */
async function getPositiveNote(
    chain: Blockchain,
    account: Account,
    assetID?: Buffer,
  ): Promise<{note: Note, witness: NoteWitness, value: bigint}> {
  // attempt to retrieve a note from wallet with positive native asset value
  let note: Note | null = null
  let noteWitness: NoteWitness | null = null

  if (!assetID) {
    assetID = Asset.nativeId()
  }

  for await (const unspentNote of account.getUnspentNotes(assetID)) {
    if (unspentNote.note.value() <= BigInt(0)) {
      continue
    }

    Assert.isNotNull(unspentNote.index)
    Assert.isNotNull(unspentNote.nullifier)

    // Try creating a witness from the note
    const unspentNoteWitness = await chain.notes.witness(unspentNote.index)

    if (unspentNoteWitness === null) {
      continue
    }

    // Found a valid note
    note = unspentNote.note
    noteWitness = unspentNoteWitness
    break
  }

  Assert.isNotNull(note)
  Assert.isNotNull(noteWitness)

  let noteValue = note.value()

  Assert.isTrue(noteValue > BigInt(0))

  return {note: note, witness: noteWitness, value: noteValue}
}

/**
 * Produces a transaction that has zero or one spend with positive value, and
 * a note which balances this value so that the transaction fee is zero or negative
 */
export async function createNegativeFeeTransaction(
  from: Account,
  to: Account,
  fee: bigint,
  chain: Blockchain,
  options: {
    expiration?: number,
    addSpend?: boolean,
  } = { expiration: 0, addSpend: false },
): Promise<Transaction> {

  Assert.isTrue(fee <= BigInt(0))
  let outputAmount = -fee

  // construct raw transaction
  const raw = new RawTransaction()
  raw.expiration = options.expiration ?? 0
  raw.fee = fee

  const addSpend = options.addSpend ?? false

  if (addSpend) {
    let posNoteData = await getPositiveNote(chain, from)
    const spendNote = posNoteData.note
    const noteWitness = posNoteData.witness
    const noteValue = posNoteData.value

    const noteHasher = new NoteHasher()
    const witness = new Witness(
      noteWitness.treeSize(),
      noteWitness.rootHash,
      noteWitness.authenticationPath,
      noteHasher,
    )

    raw.spends.push({
      note: spendNote,
      witness: witness,
    })

    outputAmount += noteValue
  }

  // add an output to produce the desired fee amount

  const outputNote = new NativeNote(
    to.publicAddress,
    outputAmount,
    'Test note for a transaction with negative fee',
    Asset.nativeId(),
    from.publicAddress,
  )

  raw.outputs.push({ note: new Note(outputNote.serialize()) })

  // create posted transaction

  const transaction = raw.post(from.spendingKey || '')

  // confirm that transaction has the desired properties

  if (addSpend) {
    Assert.isEqual(transaction.spends.length, 1)
  } else {
    Assert.isEqual(transaction.spends.length, 0)
  }
  Assert.isEqual(transaction.notes.length, 1)
  Assert.isEqual(transaction.mints.length, 0)
  Assert.isEqual(transaction.burns.length, 0)
  Assert.isEqual(transaction.fee(), fee)

  return transaction
}
