use aiken/hash.{Blake2b_224, Hash}
use aiken/interval.{Finite}
use aiken/list.{length}
use aiken/transaction.{
  InlineDatum, Input, Output, ScriptContext, Spend, Transaction,
}
use aiken/transaction/value.{is_zero, merge, negate}
use ak_381/groth16.{groth_verify, Proof, SnarkVerificationKey}
pub type VerificationKey =
  ByteArray

pub type PubKeyHash =
  Hash<Blake2b_224, VerificationKey>

pub type GameDatum {
  code_master: PubKeyHash,
  code_breaker: PubKeyHash,
  hash_solution: Int,
  guess: List<Int>,
  black_pegs: Int,
  white_pegs: Int,
  current_turn: Int,
  expiration_time: Int,
  vk: SnarkVerificationKey,
  proof: Proof,
}

pub type GameRedeemer {
  Start
  Guess
  Clue
  End
}

pub type ValueOptions {
  Equal
  Double
  Inequal
}

validator {
  pub fn mastermind(dat: GameDatum, rdm: GameRedeemer, ctx: ScriptContext) -> Bool {
    let ScriptContext { transaction, .. } = ctx

    // Check if transaction is signed by the CodeMaster
    let signed_by_code_master: Bool =
      must_be_signed_by(transaction, dat.code_master)

    // Check if transaction is signed by the CodeBreaker
    let signed_by_code_breaker: Bool =
      must_be_signed_by(transaction, dat.code_breaker)

    when rdm is {
      Start -> {
        let value_preservation: ValueOptions = value_check(ctx)

        // Find outputs sent back to the contract
        expect [output_to_contract] = find_own_outputs(ctx)

        // Get new datum
        expect InlineDatum(out_datum) = output_to_contract.datum
        expect new_datum: GameDatum = out_datum

        // Get upper bound point of the transaction validity range
        expect Finite(upper_time_point) =
          transaction.validity_range.upper_bound.bound_type
        // Expiration time must be greater or equal than the upper Validity range point + 20 mins 
        let is_expiration_correct: Bool =
          upper_time_point + 1200000 <= new_datum.expiration_time
        // Get lower bound point of the transaction validity range
        expect Finite(lower_time_point) =
          transaction.validity_range.lower_bound.bound_type

        and {
          trace @"[Fail] Check current turn"
          // Current turn set by CM must be 0
          dat.current_turn == 0,
          trace @"[Fail] Check double value"
          // CB must lock the double of CM value lock
          value_preservation == Double,
          trace @"[Fail] Guess length"
          // The guess is sequence of 4 balls 
          // TODO: Must check non valid balls ids
          length(new_datum.guess) == 4,
          trace @"[Fail] Check new turn "
          // This turn must set to 1
          new_datum.current_turn == 1,
          trace @"[Fail] Check sign"
          // The codebreaker signature must be the same who do the tx.
          must_be_signed_by(transaction, new_datum.code_breaker),
          trace @"[Fail] Check signatures integrety"
          // CodeMaster signature integrity check
          new_datum.code_master == dat.code_master,
          trace @"[Fail] Check hashsol integrity"
          // Hash Solution integrity check
          new_datum.hash_solution == dat.hash_solution,
          trace @"[Fail] Check expiration"
          // Expiration time must be greater or equal than the upper Validity range point + 20 mins 
          is_expiration_correct,
          trace @"[Fail] Check validity range length"
          // The valid range must lesser than 20 min, so that the expiration time is in a nearer time.
          // This prevents to send a tx with that locks the game by setting a expiration time too far away in the future
          upper_time_point - lower_time_point <= 1200000,
        }
      }
      Guess -> {
        let value_preservation: ValueOptions = value_check(ctx)

        // Find outputs sent back to the contract
        expect [output_to_contract] = find_own_outputs(ctx)

        // Get new datum
        expect InlineDatum(out_datum) = output_to_contract.datum
        expect new_datum: GameDatum = out_datum

        // In Guess and Clue turns the integrity of signatures must remain.
        let correct_signatures: Bool =
          new_datum.code_master == dat.code_master && new_datum.code_breaker == dat.code_breaker

        and {
          trace @"[Fail] Check turn"
          // Next turn must be the sucessor of the current turn
          dat.current_turn + 1 == new_datum.current_turn,
          // The turn must lower than 10 to play
          trace @"[Fail] Turn greater than 10"
          dat.current_turn < 10,
          // Code Breaker always plays in odd turns
          trace @"[Fail] Check modulo turn"
          new_datum.current_turn % 2 == 1,
          // The guess is sequence of 4 balls 
          // TODO: Must check non valid balls ids
          trace @"[Fail] Length guess integrity check"
          length(new_datum.guess) == 4,
          // Value persistence check.
          trace @"[Fail] Value preservatation"
          value_preservation == Equal,
          // Must signed by Code Breaker
          trace @"[Fail] Signature check"
          signed_by_code_breaker,
          // Signature integrity check
          trace @"[Fail] Datum signature check"
          correct_signatures,
          // Hash Solution integrity check
          trace @"[Fail] Hashsol datum integrity check"
          new_datum.hash_solution == dat.hash_solution,
          // Verification key integrity check
          trace @"[Fail] vk datum integrity check"
          new_datum.vk == dat.vk,
          // Each turn the expiration time is pushed 20 min in the future.
          trace @"[Fail] Expiration time check"
          new_datum.expiration_time == dat.expiration_time + 1200000,
        }
      }
      Clue -> {
        let value_preservation: ValueOptions = value_check(ctx)

        // Find outputs sent back to the contract
        expect [output_to_contract] = find_own_outputs(ctx)

        // Get new datum
        expect InlineDatum(out_datum) = output_to_contract.datum
        expect new_datum: GameDatum = out_datum

        // In Guess and Clue turns the integrity of signatures must remain.
        let correct_signatures: Bool =
          new_datum.code_master == dat.code_master && new_datum.code_breaker == dat.code_breaker

        let public_inputs: List<Int> = list.concat(
          [dat.hash_solution],dat.guess
        ) |> list.concat(_,[new_datum.black_pegs,new_datum.white_pegs,dat.hash_solution])

        and {
          trace @"[Fail] Check turn"
          // Next turn must be the sucessor of the current turn
          dat.current_turn + 1 == new_datum.current_turn,
          // Code Master always plays in even turns
          trace @"[Fail] Check modulo turn"
          new_datum.current_turn % 2 == 0,
          // The turn must lower than 10 to play
          trace @"[Fail] Turn greater than 10n"
          dat.current_turn < 10,
          // Value persistence check.
          trace @"[Fail] Value alteration"
          value_preservation == Equal,
          // Must be signed by the 
          trace @"[Fail] CM sign check"
          signed_by_code_master,
          // Signatures integrity check
          trace @"[Fail] Datum sig integrity check"
          correct_signatures,
          // Hash solution integrity check
          trace @"[Fail] Hashsol integrity check"
          new_datum.hash_solution == dat.hash_solution,
          // Verification key integrity check
          trace @"[Fail] datum vk integrity check"
          new_datum.vk == dat.vk,
          // Each turn the expiration time is pushed 20 min in the future.
          trace @"[Fail] Expiration time check"
          new_datum.expiration_time == dat.expiration_time + 1200000,
          trace @"[Fail] Verify zk-proof"
          groth_verify(new_datum.vk, new_datum.proof, public_inputs )
        }
      }
      End -> {
        // Get lower point of the Tx Validity Range
        expect Finite(lower_time_point) =
          transaction.validity_range.lower_bound.bound_type

        // Create an interval that starts from the expiration time to Infity
        let after_expiration_interval = interval.after(dat.expiration_time)

        // A Tx cannot be submitted before the lower bound point
        // Check if this lower bound point is after de expiration time (by checking if it inside the expiration time to inf interval)
        // Therefore, check if the Tx is submitted after the expiration date.
        let expiration_reached: Bool =
          interval.contains(after_expiration_interval, lower_time_point)

        or {
          // Code Breaker wins
          dat.black_pegs == 4 && signed_by_code_breaker && dat.current_turn <= 10,
          // Code Master wins
          dat.black_pegs < 4 && dat.current_turn == 10 && signed_by_code_master,
          // Code Breaker wins by default
          expiration_reached && dat.current_turn % 2 == 1 && signed_by_code_breaker,
          // Code Master wins by default
          expiration_reached && dat.current_turn % 2 == 0 && signed_by_code_master,
          // Code Master withdraw
          dat.current_turn == 0 && signed_by_code_master,
        }
      }
    }
  }
}

// Helper functions 

// Get input from the script.
fn find_own_input(ctx: ScriptContext) -> Input {
  expect Spend(output_ref) = ctx.purpose

  expect Some(input) =
    ctx.transaction.inputs
      |> transaction.find_input(output_ref)
  input
}

// Get outputs to the script.
fn find_own_outputs(ctx: ScriptContext) -> List<Output> {
  let own_input: Input = find_own_input(ctx)
  let onw_script_address = own_input.output.address

  let outputs = ctx.transaction.outputs

  expect [own_output] =
    list.filter(
      outputs,
      fn(output: Output) { output.address == onw_script_address },
    )
  [own_output]
}

// Check if transaction is signed by...
fn must_be_signed_by(transaction: Transaction, vk: PubKeyHash) {
  list.has(transaction.extra_signatories, vk)
}

// 

fn value_check(ctx: ScriptContext) -> ValueOptions {
  // Find input from this spending contract
  let input_from_contract: Input = find_own_input(ctx)

  // Find outputs sent back to the contract
  expect [output_to_contract] = find_own_outputs(ctx)

  // Check if is equal
  let is_equal: Bool =
    is_zero(
      merge(input_from_contract.output.value, negate(output_to_contract.value)),
    )

  let is_double: Bool =
    is_zero(
      merge(
        merge(
          input_from_contract.output.value,
          input_from_contract.output.value,
        ),
        negate(output_to_contract.value),
      ),
    )

  if is_equal {
    Equal
  } else if is_double {
    Double
  } else {
    Inequal
  }
}
