use aiken/hash.{Blake2b_224, Hash}
use aiken/list.{ and, length}
use aiken/transaction.{Transaction, ScriptContext, Spend, ValidityRange, Input, NoDatum, ScriptPurpose, Output, InlineDatum}
use aiken/transaction/credential.{VerificationKey,ScriptCredential}
use aiken/interval.{Finite}

type VerificationKeyHash =
  Hash<Blake2b_224, VerificationKey>

type Datum {
  owner: Hash<Blake2b_224, VerificationKey>,
  state: Int,
  unlockTime: Int
}
 
type Redeemer {
  StartClaim
  FinishClaim
}

//CHANGE THIS TO ALLOW DIFFERENT TIME BETWEEN FIRST AND SECOND TRANSACTION
const minutesLocked=10

validator {
  fn vault(datum: Datum, redeemer: Redeemer, ctx: ScriptContext) -> Bool {


    let ownScriptHash =get_own_hash(ctx.purpose, ctx.transaction.inputs)

    let timeToUnlock = minutesLocked*60*1000 //10 minutes in milliseconds
    let upperBound=get_upper_bound(ctx.transaction.validity_range)//current transaction time 
    let nextBound=upperBound+timeToUnlock //next transaction unlock

    when redeemer is {
        StartClaim -> and([
                        //only one datum in input
                        only_one_sc_input(ctx.transaction.inputs),
                        //time slot validity is 5 mins of the transaction so upper - lower limit
                        is_validity_range_correct(ctx.transaction.validity_range, 5),
                        //owner should do it
                        must_be_signed_by(ctx.transaction, datum.owner),
                        //I add 10 minutes more so validate datum
                        validate_update_datum(datum, ctx.transaction.outputs, ownScriptHash, nextBound),
                        //Only nfts with state equal to 0 can be updated
                        datum.state==0
                        ])
        FinishClaim -> and([
                        //only nfts that were in state 1 can be claimed now
                        datum.state==1,
                        //one sc input
                        only_one_sc_input(ctx.transaction.inputs),
                        //signed by the owner
                        must_be_signed_by(ctx.transaction, datum.owner),
                        //after deadline
                        is_validity_range_after(ctx.transaction.validity_range, datum.unlockTime),
                        ])
        _ -> False
    }
 
  }
}


fn get_own_hash(purpose: ScriptPurpose, txInputs: List<Input>) {
  expect Spend(a) =
    purpose

  let inputList =
    list.filter(
      txInputs,
      fn(x) {
        when x.output_reference is {
          _ ->
            False
          a ->
            True
        }
      },
    )

  expect Some(maybeInput) =
    list.head(inputList)
  when maybeInput.output.address.payment_credential is {
    ScriptCredential(a) ->
      a
    _ ->
      error
  }
}

fn must_be_signed_by(transaction: Transaction, vk: VerificationKeyHash) {
  list.has(transaction.extra_signatories, vk)
}

fn only_one_sc_input(txInputs: List<Input>) {
  let inputList =
    list.filter(
      txInputs,
      fn(input) {
        when input.output.datum is {
          NoDatum ->
            False
          _ ->
            True
        }
      },
    )
  length(inputList) == 1
}

fn is_validity_range_correct(range: ValidityRange, minutes: Int){

    let lower = when range.lower_bound.bound_type is {
        Finite(now) -> now
        _ -> error
    }

    let upper = when range.upper_bound.bound_type is {
        Finite(now) -> now
        _ -> error
    }

    upper-lower<minutes*60*1000   

}

fn is_validity_range_after(range: ValidityRange, deadline: Int){


    let upper = when range.upper_bound.bound_type is {
        Finite(now) -> now
        _ -> error
    }

    upper>deadline   

}

fn get_upper_bound(range: ValidityRange){

    let upper = when range.upper_bound.bound_type is {
        Finite(now) -> now
        _ -> error
    }
    upper
}

fn validate_update_datum(datum: Datum,txOutputs: List<Output>,contract: ByteArray,nextBound:Int) {
  let outputList =
    list.filter(
      txOutputs,
      fn(output) {
        when output.datum is {
          NoDatum ->
            False
          _ ->
            True
        }
      },
    )

  let outputToContract =
    list.filter(
      outputList,
      fn(output) {
        when output.address.payment_credential is {
          ScriptCredential(a) ->
            if a == contract {
              True
            } else {
              False
            }
          _ ->
            False
        }
      },
    )


    expect Some(maybeOutput) = list.head(outputToContract)
    expect InlineDatum(outputDatum) = maybeOutput.datum
    expect parsedDatum: Datum = outputDatum

    let newDatum =
      Datum {
        owner: datum.owner,
        state: 1,
        unlockTime: nextBound

      }
    and([length(outputToContract) == 1, newDatum == parsedDatum])
  
}
