use aiken/hash.{Blake2b_224, Hash}
use aiken/interval.{Finite}
use aiken/list.{length}
use aiken/transaction.{
  InlineDatum, Input, Output, ScriptContext, Spend, Transaction,
}
use aiken/transaction/value.{flatten}

type VerificationKey =
  ByteArray

type PubKeyHash =
  Hash<Blake2b_224, VerificationKey>

pub type SnarkVerificationKey {
  nPublic: Int,
  // G1Element
  vkAlpha: ByteArray,
  // G2Element
  vkBeta: ByteArray,
  // G2Element
  vkGamma: ByteArray,
  // G2Element
  vkDelta: ByteArray,
  // List<G2Element>
  vkAlphaBeta: List<ByteArray>,
  // List<G1Element>
  vkIC: List<ByteArray>,
}

//
pub type Proof {
  // G1Element 
  piA: ByteArray,
  // G2Element
  piB: ByteArray,
  // G1Element
  piC: ByteArray,
}

type GameDatum {
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

type GameRedeemer {
  Start
  Guess
  Clue
  End
}

validator {
  fn mastermind(dat: GameDatum, rdm: GameRedeemer, ctx: ScriptContext) -> Bool {
    let ScriptContext { transaction, .. } = ctx

    // Find input from this spending contract
    let input_from_contract: Input = find_own_input(ctx)
    expect [(policyid1, token_name1, amount1)] =
      flatten(input_from_contract.output.value)

    // Find outputs sent back to the contract
    expect [output_to_contract] = find_own_outputs(ctx)
    expect [(policyid2, token_name2, amount2)] =
      flatten(output_to_contract.value)

    // Check if the amount sent to the contract is equal the amount previously locked.
    let is_equal: Bool = and {
        policyid1 == policyid2,
        token_name1 == token_name2,
        amount1 == amount2,
      }

    // Check if the amount sent to the contract is twice the amount initially locked.
    let is_double: Bool = and {
        policyid1 == policyid2,
        token_name1 == token_name2,
        amount1 == amount2 * 2,
      }
    // Check if transaction is signed by the CodeMaster
    let signed_by_code_master: Bool =
      must_be_signed_by(transaction, dat.code_master)

    // Check if transaction is signed by the CodeBreaker
    let signed_by_code_breaker: Bool =
      must_be_signed_by(transaction, dat.code_breaker)

    // Get new datum
    expect InlineDatum(out_datum) = output_to_contract.datum
    expect new_datum: GameDatum = out_datum

    // In Guess and Clue turns the integrity of signatures must remain.
    let correct_signatures: Bool =
      new_datum.code_master == dat.code_master && new_datum.code_breaker == dat.code_breaker

    when rdm is {
      Start -> {
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
          // Current turn set by CM must be 0
          dat.current_turn == 0,
          // CB must lock the double of CM value lock
          is_double,
          // The guess is sequence of 4 balls 
          // TODO: Must check non valid balls ids
          length(dat.guess) == 4,
          // This turn must set to 1
          new_datum.current_turn == 1,
          // The codebreaker signature must be the same who do the tx.
          must_be_signed_by(transaction, new_datum.code_breaker),
          // CodeMaster signature integrity check
          new_datum.code_master == dat.code_master,
          // Hash Solution integrity check
          new_datum.hash_solution == dat.hash_solution,
          // Expiration time must be greater or equal than the upper Validity range point + 20 mins 
          is_expiration_correct,
          // The valid range must lesser than 20 min, so that the expiration time is in a nearer time.
          // This prevents to send a tx with that locks the game by setting a expiration time too far away in the future
          upper_time_point - lower_time_point <= 1200000,
        }
      }
      Guess -> and {
          // Next turn must be the sucessor of the current turn
          dat.current_turn + 1 == new_datum.current_turn,
          // The turn must lower than 10 to play
          dat.current_turn < 10,
          // Code Breaker always plays in odd turns
          new_datum.current_turn % 2 == 1,
          // Value persistence check.
          is_equal,
          // Must signed by Code Breaker
          signed_by_code_breaker,
          // Signature integrity check
          correct_signatures,
          // Hash Solution integrity check
          new_datum.hash_solution == dat.hash_solution,
          // Verification key integrity check
          new_datum.vk == dat.vk,
          // Each turn the expiration time is pushed 20 min in the future.
          new_datum.expiration_time == dat.expiration_time + 1200000,
        }

      Clue -> and {
          // Next turn must be the sucessor of the current turn
          dat.current_turn + 1 == new_datum.current_turn,
          // Code Master always plays in even turns
          new_datum.current_turn % 2 == 0,
          // The turn must lower than 10 to play
          dat.current_turn < 10,
          // Value persistence check.
          is_equal,
          // Must be signed by the 
          signed_by_code_master,
          // Signatures integrity check
          correct_signatures,
          // Hash solution integrity check
          new_datum.hash_solution == dat.hash_solution,
          // Verification key integrity check
          new_datum.vk == dat.vk,
          // Each turn the expiration time is pushed 20 min in the future.
          new_datum.expiration_time == dat.expiration_time + 1200000,
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
          dat.black_pegs == 4 && signed_by_code_breaker,
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
  expect Spend(output_ref) = ctx.purpose

  let own_outputs =
    ctx.transaction.outputs
      |> transaction.find_script_outputs(output_ref.transaction_id.hash)
  own_outputs
}

// Check if transaction is signed by...
fn must_be_signed_by(transaction: Transaction, vk: PubKeyHash) {
  list.has(transaction.extra_signatories, vk)
}
