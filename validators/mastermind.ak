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

type ZeroVerificationKey {
  n_public: Int,
  vk_alpha1: List<Int>,
  vk_beta2: List<List<Int>>,
  vk_gamma2: List<List<Int>>,
  vk_delta2: List<List<Int>>,
  vk_alphabeta12: List<List<List<Int>>>,
  ic: List<List<Int>>,
}

type Proof {
  pi_a: List<Int>,
  pi_b: List<List<Int>>,
  pi_c: List<Int>,
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
  vk: ZeroVerificationKey,
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

    let input_from_contract: Input = find_own_input(ctx)
    expect [(policyid1, token_name1, amount1)] =
      flatten(input_from_contract.output.value)

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
    let signed_by_code_master: Bool =
      must_be_signed_by(transaction, dat.code_master)

    let signed_by_code_breaker: Bool =
      must_be_signed_by(transaction, dat.code_breaker)

    expect InlineDatum(out_datum) = output_to_contract.datum
    expect new_datum: GameDatum = out_datum

    let correct_signatures: Bool =
      new_datum.code_master == dat.code_master && new_datum.code_breaker == dat.code_breaker

    when rdm is {
      Start -> {
        expect Finite(upper_time_point) =
          transaction.validity_range.upper_bound.bound_type
        let is_expiration_correct: Bool =
          upper_time_point + 1200000 <= new_datum.expiration_time
        expect Finite(lower_time_point) =
          transaction.validity_range.lower_bound.bound_type

        and {
          dat.current_turn == 0,
          is_double,
          length(dat.guess) == 4,
          new_datum.current_turn == 1,
          must_be_signed_by(transaction, new_datum.code_breaker),
          new_datum.code_master == dat.code_master,
          new_datum.hash_solution == dat.hash_solution,
          is_expiration_correct,
          upper_time_point - lower_time_point <= 1200000,
        }
      }
      Guess -> and {
          dat.current_turn + 1 == new_datum.current_turn,
          dat.current_turn % 2 == 0,
          dat.current_turn <= 10,
          is_equal,
          signed_by_code_breaker,
          correct_signatures,
          new_datum.vk == dat.vk,
          new_datum.expiration_time == dat.expiration_time + 1200000,
        }

      Clue -> and {
          dat.current_turn + 1 == new_datum.current_turn,
          dat.current_turn % 2 == 1,
          dat.current_turn <= 10,
          is_equal,
          signed_by_code_master,
          correct_signatures,
          new_datum.hash_solution == dat.hash_solution,
          new_datum.vk == dat.vk,
          new_datum.expiration_time == dat.expiration_time + 1200000,
        }

      End -> {
        expect Finite(lower_time_point) =
          transaction.validity_range.lower_bound.bound_type

        let after_expiration_interval = interval.after(dat.expiration_time)

        let expiration_reached: Bool =
          interval.contains(after_expiration_interval, lower_time_point)

        or {
          dat.black_pegs == 4 && signed_by_code_breaker,
          dat.black_pegs < 4 && dat.current_turn == 10 && signed_by_code_master,
          expiration_reached && dat.current_turn % 2 == 1 && signed_by_code_breaker,
          expiration_reached && dat.current_turn % 2 == 0 && signed_by_code_master,
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
