use aiken/bytearray
use aiken/cbor.{serialise}
use aiken/dict
use aiken/hash.{Blake2b_224, Hash, blake2b_256}
use aiken/interval.{Finite, Interval, IntervalBound}
use aiken/transaction.{
  Input, NoDatum, Output, OutputReference, ScriptContext,
  ScriptPurpose, Spend, Transaction, TransactionId, ValidityRange, DatumHash
}
use aiken/transaction/credential.{Address, ScriptCredential}
use aiken/transaction/value.{Value, from_asset, from_lovelace, merge}
use mastermind.{
  Clue, End, GameDatum, GameRedeemer, Guess,  Start,
  VerificationKey, mastermind,
}
use ak_381/groth16.{Proof, SnarkVerificationKey}

fn gameValue() -> Value {
  merge(
    from_lovelace(1500000),
    from_asset(
      #"d47ea75b975baa070978b1acd882029d2f95541d678d06bd63b4b9aa",
      #"48796472414441",
      15000000,
    ),
  )
}


test hash_equal () {
  let snark_vk =
    SnarkVerificationKey {
      nPublic: 8,
      vkAlpha: #"910df641298bf37a09468eb8eefe36cd9333d2698abee298b25521570d19a04c7482b35ed0392a8275ced89cbfa44f39",
      vkBeta: #"a13e94f2ba50b23446d56fb039cbd357875acbab92ccff7471e7ca79d2748684e6c4c322dce042d33bbfb23bb22cc57d187ca5634ddad5994f1f9a2c5d9d98d8c1916d767bc9aa23de1549a12640aef88543223ac5828d0520007c140f9e8716",
      vkGamma: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      vkDelta: #"8d835235db743dab2ec2817dc2545aaf4eab5997ce1df83195733c6f7ca9619593f66d06153b294f9dc9bf4e45232534084068327fdbcc5f6bdc07bf4dd6cdd8962c75112842fd7e92b2f13da4c565c0fcff2818e34b768856dfa8041bed7b9e",
      vkAlphaBeta: [
        #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      ],
      vkIC: [
        #"aae31c7beb5a2f92b3f9be7ff278c841dc15769244c5cb81b95858fcdfad34621a86f956e1de57cb104050302cc8ae09",
        #"b721c142b4c9c1de3570dd30d6ec1fc009deef3319ecd0c681c37301eab8fa9e625d4457b3376de26c83d3a6dc63b290",
        #"b1e0a4b9324277450efd02db4b7d0451a6d556f6bd61fef2df9a7ce7fd321b27e8a0e5943967b1f82856aa87a40f17ba",
        #"ad3f4b41f48a13eceda136882dfc5cc543cab7714a0abdedf7cc85fa58b4b2c69c1a8f74bc0d89901f2a4ab717a3e412",
        #"84e0a2709079a6c2b0ce1d3e19242d7a729e19936e8a9a7297055545048d1d7d14bd62baecb8bdd6b33809368461a5c9",
        #"b33e6b2bfc9f29ef766f6167bf6b3873e073eb79a55153b1ebba15187593273bf64ef7e155d1118535bab8d16676c27e",
        #"89ce67829659a866237178e52ecbfaeba754a9db3bcc097aa230cd0af9daae18346dc51685ca4ccf650094698a7115c9",
        #"8c6420bca64925df0c00b45eba87e142b04a12f86013e78c3a97c73922910b94e0647c8d60721d5749e5f5fe739dcb28",
        #"9142ab2d492fbd93323976cc16057301f4f078b273898fbf98e2c0c6aded69f54b0beae793855599d106400de6c85947"
      ],
    }

  let proof_1 =
    Proof {
      piA: #"",
      piB: #"",
      piC: #"",
    }

  let game_datum_4 =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [1, 1, 1, 4],
      black_pegs: 2,
      white_pegs: 0,
      current_turn: 4,
      expiration_time: 600000 + 1200000 + 1200000 + 1200000 + 1200000,
      vk: snark_vk,
      proof: proof_1,
    }

  let game_datum_hash_4 = blake2b_256(serialise(game_datum_4))

  let game_datum_5 =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [1, 1, 1, 4],
      black_pegs: 2,
      white_pegs: 0,
      current_turn: 4,
      expiration_time: 600000 + 1200000 + 1200000 + 1200000 + 1200000,
      vk: snark_vk,
      proof: proof_1,
    }

  let game_datum_hash_5 = blake2b_256(serialise(game_datum_5))

  game_datum_hash_5 == game_datum_hash_4
}

// Secret : [1,2,3,4]

test turn1() {
  // === GameDatum Definition ===

  let snark_vk =
    SnarkVerificationKey {
      nPublic: 8,
      vkAlpha: #"910df641298bf37a09468eb8eefe36cd9333d2698abee298b25521570d19a04c7482b35ed0392a8275ced89cbfa44f39",
      vkBeta: #"a13e94f2ba50b23446d56fb039cbd357875acbab92ccff7471e7ca79d2748684e6c4c322dce042d33bbfb23bb22cc57d187ca5634ddad5994f1f9a2c5d9d98d8c1916d767bc9aa23de1549a12640aef88543223ac5828d0520007c140f9e8716",
      vkGamma: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      vkDelta: #"8d835235db743dab2ec2817dc2545aaf4eab5997ce1df83195733c6f7ca9619593f66d06153b294f9dc9bf4e45232534084068327fdbcc5f6bdc07bf4dd6cdd8962c75112842fd7e92b2f13da4c565c0fcff2818e34b768856dfa8041bed7b9e",
      vkAlphaBeta: [
        #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      ],
      vkIC: [
        #"aae31c7beb5a2f92b3f9be7ff278c841dc15769244c5cb81b95858fcdfad34621a86f956e1de57cb104050302cc8ae09",
        #"b721c142b4c9c1de3570dd30d6ec1fc009deef3319ecd0c681c37301eab8fa9e625d4457b3376de26c83d3a6dc63b290",
        #"b1e0a4b9324277450efd02db4b7d0451a6d556f6bd61fef2df9a7ce7fd321b27e8a0e5943967b1f82856aa87a40f17ba",
        #"ad3f4b41f48a13eceda136882dfc5cc543cab7714a0abdedf7cc85fa58b4b2c69c1a8f74bc0d89901f2a4ab717a3e412",
        #"84e0a2709079a6c2b0ce1d3e19242d7a729e19936e8a9a7297055545048d1d7d14bd62baecb8bdd6b33809368461a5c9",
        #"b33e6b2bfc9f29ef766f6167bf6b3873e073eb79a55153b1ebba15187593273bf64ef7e155d1118535bab8d16676c27e",
        #"89ce67829659a866237178e52ecbfaeba754a9db3bcc097aa230cd0af9daae18346dc51685ca4ccf650094698a7115c9",
        #"8c6420bca64925df0c00b45eba87e142b04a12f86013e78c3a97c73922910b94e0647c8d60721d5749e5f5fe739dcb28",
        #"9142ab2d492fbd93323976cc16057301f4f078b273898fbf98e2c0c6aded69f54b0beae793855599d106400de6c85947"
      ],
    }

  let proof_1 =
    Proof {
      piA: #"",
      piB: #"",
      piC: #"",
    }

  let game_datum_0 =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [],
      black_pegs: 0,
      white_pegs: 0,
      current_turn: 0,
      expiration_time: 0,
      vk: snark_vk,
      proof: proof_1,
    }

  let game_datum_hash_0 = blake2b_256(serialise(game_datum_0))

  // === Purpose Definition ===
  let tx_id =
    TransactionId {
      hash: #"5e5d8ed3ae7e640a0466908d2ed26011b3e0f7dc5759c5f6790b04927fd50fd7",
    }

  // This is the UTxO of the script input to be spent.
  let script_outref = OutputReference { transaction_id: tx_id, output_index: 0 }

  let purpose: ScriptPurpose = Spend(script_outref)

  // === Transaction Definition ===
  // * UTxO of the turn 0
  let utxo_0: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: gameValue(),
      datum: DatumHash(game_datum_hash_0),
      reference_script: None,
    }

  // * Take the UTxO of turn 0 as input
  // Note: This is an input that comes from the script, so it is the same that the one that is contained in Spend purpose.
  let input_0: Input = Input { output_reference: script_outref, output: utxo_0 }

  // * Create new Game Datum
  let game_datum_1: Data =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [4, 3, 2, 1],
      black_pegs: 0,
      white_pegs: 0,
      current_turn: 1,
      expiration_time: 1200000 + 600000,
      vk: snark_vk,
      proof: proof_1,
    }

  let game_datum_hash_1 = blake2b_256(serialise(game_datum_1))

  // * Create a new output
  let output_1: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: merge(gameValue(), gameValue()),
      datum: DatumHash(game_datum_hash_1),
      reference_script: None,
    }

  // * Define sigs to be included in extra_signatories Tx field.
  let signatures_1: List<Hash<Blake2b_224, VerificationKey>> =
    [#"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f"]

  // * Define validity range + 300000 (5min) to lower and upper bound
  let val_range_1: ValidityRange =
    Interval {
      lower_bound: IntervalBound {
        bound_type: Finite(300000),
        is_inclusive: True,
      },
      upper_bound: IntervalBound {
        bound_type: Finite(600000),
        is_inclusive: True,
      },
    }

  // * Transaction values wrap-up
  let tx: Transaction =
    transaction.placeholder()
      |> fn(tx) {
           Transaction {
             ..tx,
             inputs: [input_0],
             outputs: [output_1],
             extra_signatories: signatures_1,
             validity_range: val_range_1,
             datums: dict.new() |> dict.insert(key: game_datum_hash_1, value: game_datum_1, compare: bytearray.compare),
           }
         }

  // === Redeemer Definition ===
  let rdm: GameRedeemer = Start

  let ctx: ScriptContext = ScriptContext { transaction: tx, purpose }

  mastermind(game_datum_0, rdm, ctx)
}

test turn2() {
  // === GameDatum Definition ===

  let snark_vk =
    SnarkVerificationKey {
      nPublic: 8,
      vkAlpha: #"910df641298bf37a09468eb8eefe36cd9333d2698abee298b25521570d19a04c7482b35ed0392a8275ced89cbfa44f39",
      vkBeta: #"a13e94f2ba50b23446d56fb039cbd357875acbab92ccff7471e7ca79d2748684e6c4c322dce042d33bbfb23bb22cc57d187ca5634ddad5994f1f9a2c5d9d98d8c1916d767bc9aa23de1549a12640aef88543223ac5828d0520007c140f9e8716",
      vkGamma: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      vkDelta: #"8d835235db743dab2ec2817dc2545aaf4eab5997ce1df83195733c6f7ca9619593f66d06153b294f9dc9bf4e45232534084068327fdbcc5f6bdc07bf4dd6cdd8962c75112842fd7e92b2f13da4c565c0fcff2818e34b768856dfa8041bed7b9e",
      vkAlphaBeta: [
        #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      ],
      vkIC: [
        #"aae31c7beb5a2f92b3f9be7ff278c841dc15769244c5cb81b95858fcdfad34621a86f956e1de57cb104050302cc8ae09",
        #"b721c142b4c9c1de3570dd30d6ec1fc009deef3319ecd0c681c37301eab8fa9e625d4457b3376de26c83d3a6dc63b290",
        #"b1e0a4b9324277450efd02db4b7d0451a6d556f6bd61fef2df9a7ce7fd321b27e8a0e5943967b1f82856aa87a40f17ba",
        #"ad3f4b41f48a13eceda136882dfc5cc543cab7714a0abdedf7cc85fa58b4b2c69c1a8f74bc0d89901f2a4ab717a3e412",
        #"84e0a2709079a6c2b0ce1d3e19242d7a729e19936e8a9a7297055545048d1d7d14bd62baecb8bdd6b33809368461a5c9",
        #"b33e6b2bfc9f29ef766f6167bf6b3873e073eb79a55153b1ebba15187593273bf64ef7e155d1118535bab8d16676c27e",
        #"89ce67829659a866237178e52ecbfaeba754a9db3bcc097aa230cd0af9daae18346dc51685ca4ccf650094698a7115c9",
        #"8c6420bca64925df0c00b45eba87e142b04a12f86013e78c3a97c73922910b94e0647c8d60721d5749e5f5fe739dcb28",
        #"9142ab2d492fbd93323976cc16057301f4f078b273898fbf98e2c0c6aded69f54b0beae793855599d106400de6c85947"
      ],
    }

  let proof_1 =
    Proof {
      piA: #"",
      piB: #"",
      piC: #"",
    }

  

  let game_datum_1 =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [4, 3, 2, 1],
      black_pegs: 0,
      white_pegs: 0,
      current_turn: 1,
      expiration_time: 1200000 + 600000,
      vk: snark_vk,
      proof: proof_1,
    }

  let game_datum_hash_1 = blake2b_256(serialise(game_datum_1))

  // === Purpose Definition ===
  let tx_id =
    TransactionId {
      hash: #"ae92f6429a146ba25ba05edf5162c6bedbb8445851ab237e9e7ac3a5a72239e5",
    }

  // This is the UTxO of the script input to be spent.
  let script_outref = OutputReference { transaction_id: tx_id, output_index: 0 }

  let purpose: ScriptPurpose = Spend(script_outref)

  // === Transaction Definition ===
  // * UTxO of the turn 1
  let utxo_1: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: gameValue(),
      datum: DatumHash(game_datum_hash_1),
      reference_script: None,
    }

  // * Take the UTxO of turn 1 as input
  // Note: This is an input that comes from the script, so it is the same that the one that is contained in Spend purpose.
  let input_1: Input = Input { output_reference: script_outref, output: utxo_1 }

  // Generate proof 2
  let proof_2 =
    Proof {
      piA: #"972132cdfb134c36e0160ca01747460cffd948d70b0a8437d7f339ac505dada7823309187d60059af3c088f76f6d69aa",
      piB: #"840cc65995a95c5a9d639324f56202ffe280be5d8a34301f8e78d6d5844fb549918f310a4f81b5863d4ac9e37be0f4a4131f10fbd82429378e00bcc3574d11ffd86db203271a050ec1e53c62e8cf3a025d4e84962ae56c21d9c2949943c8b602",
      piC: #"8a957cd1045dda7f31f3747253317aa63a3f590a8423ec8665495e41b23326bd76ae6bbc3e7137b1a9452d4ccb6050b9",
    }

  // * Create new Game Datum
  let game_datum_2: Data =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [4, 3, 2, 1],
      black_pegs: 0,
      white_pegs: 4,
      current_turn: 2,
      expiration_time: 600000 + 1200000 + 1200000,
      vk: snark_vk,
      proof: proof_2,
    }

  let game_datum_hash_2 = blake2b_256(serialise(game_datum_2))

  // * Create a new output
  let output_2: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: gameValue(),
      datum: DatumHash(game_datum_hash_2),
      reference_script: None,
    }

  // * Define sigs to be included in extra_signatories Tx field.
  let signatures_2: List<Hash<Blake2b_224, VerificationKey>> =
    [#"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f"]

  // * Define validity range + 300000 (5min) to lower and upper bound
  let val_range_2: ValidityRange =
    Interval {
      lower_bound: IntervalBound {
        bound_type: Finite(1 + 300000 + 300000),
        is_inclusive: True,
      },
      upper_bound: IntervalBound {
        bound_type: Finite(600000 + 300000),
        is_inclusive: True,
      },
    }

  // * Transaction values wrap-up
  let tx: Transaction =
    transaction.placeholder()
      |> fn(tx) {
           Transaction {
             ..tx,
             inputs: [input_1],
             outputs: [output_2],
             extra_signatories: signatures_2,
             validity_range: val_range_2,
             datums: dict.new() |> dict.insert(key: game_datum_hash_2, value: game_datum_2, compare: bytearray.compare),
           }
         }

  // === Redeemer Definition ===
  let rdm: GameRedeemer = Clue

  let ctx: ScriptContext = ScriptContext { transaction: tx, purpose }

  mastermind(game_datum_1, rdm, ctx)
}

test turn3() {
  // === GameDatum Definition ===

  let snark_vk =
    SnarkVerificationKey {
      nPublic: 8,
      vkAlpha: #"910df641298bf37a09468eb8eefe36cd9333d2698abee298b25521570d19a04c7482b35ed0392a8275ced89cbfa44f39",
      vkBeta: #"a13e94f2ba50b23446d56fb039cbd357875acbab92ccff7471e7ca79d2748684e6c4c322dce042d33bbfb23bb22cc57d187ca5634ddad5994f1f9a2c5d9d98d8c1916d767bc9aa23de1549a12640aef88543223ac5828d0520007c140f9e8716",
      vkGamma: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      vkDelta: #"8d835235db743dab2ec2817dc2545aaf4eab5997ce1df83195733c6f7ca9619593f66d06153b294f9dc9bf4e45232534084068327fdbcc5f6bdc07bf4dd6cdd8962c75112842fd7e92b2f13da4c565c0fcff2818e34b768856dfa8041bed7b9e",
      vkAlphaBeta: [
        #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      ],
      vkIC: [
        #"aae31c7beb5a2f92b3f9be7ff278c841dc15769244c5cb81b95858fcdfad34621a86f956e1de57cb104050302cc8ae09",
        #"b721c142b4c9c1de3570dd30d6ec1fc009deef3319ecd0c681c37301eab8fa9e625d4457b3376de26c83d3a6dc63b290",
        #"b1e0a4b9324277450efd02db4b7d0451a6d556f6bd61fef2df9a7ce7fd321b27e8a0e5943967b1f82856aa87a40f17ba",
        #"ad3f4b41f48a13eceda136882dfc5cc543cab7714a0abdedf7cc85fa58b4b2c69c1a8f74bc0d89901f2a4ab717a3e412",
        #"84e0a2709079a6c2b0ce1d3e19242d7a729e19936e8a9a7297055545048d1d7d14bd62baecb8bdd6b33809368461a5c9",
        #"b33e6b2bfc9f29ef766f6167bf6b3873e073eb79a55153b1ebba15187593273bf64ef7e155d1118535bab8d16676c27e",
        #"89ce67829659a866237178e52ecbfaeba754a9db3bcc097aa230cd0af9daae18346dc51685ca4ccf650094698a7115c9",
        #"8c6420bca64925df0c00b45eba87e142b04a12f86013e78c3a97c73922910b94e0647c8d60721d5749e5f5fe739dcb28",
        #"9142ab2d492fbd93323976cc16057301f4f078b273898fbf98e2c0c6aded69f54b0beae793855599d106400de6c85947"
      ],
    }

  let proof_2 =
    Proof {
      piA: #"972132cdfb134c36e0160ca01747460cffd948d70b0a8437d7f339ac505dada7823309187d60059af3c088f76f6d69aa",
      piB: #"840cc65995a95c5a9d639324f56202ffe280be5d8a34301f8e78d6d5844fb549918f310a4f81b5863d4ac9e37be0f4a4131f10fbd82429378e00bcc3574d11ffd86db203271a050ec1e53c62e8cf3a025d4e84962ae56c21d9c2949943c8b602",
      piC: #"8a957cd1045dda7f31f3747253317aa63a3f590a8423ec8665495e41b23326bd76ae6bbc3e7137b1a9452d4ccb6050b9",
    }

  let game_datum_2 =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [4, 1, 1, 1],
      black_pegs: 0,
      white_pegs: 2,
      current_turn: 2,
      expiration_time: 600000 + 1200000 + 1200000,
      vk: snark_vk,
      proof: proof_2,
    }

  let game_datum_hash_2 = blake2b_256(serialise(game_datum_2))
  // === Purpose Definition ===
  let tx_id =
    TransactionId {
      hash: #"41ad48c17cd23daada542e321353130ea5e502223c2247216165f5ccf1a14bea",
    }

  // This is the UTxO of the script input to be spent.
  let script_outref = OutputReference { transaction_id: tx_id, output_index: 0 }

  let purpose: ScriptPurpose = Spend(script_outref)

  // === Transaction Definition ===
  // * UTxO of the turn 1
  let utxo_2: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: from_lovelace(20),
      datum: DatumHash(game_datum_hash_2),
      reference_script: None,
    }

  // * Take the UTxO of turn 1 as input
  // Note: This is an input that comes from the script, so it is the same that the one that is contained in Spend purpose.
  let input_2: Input = Input { output_reference: script_outref, output: utxo_2 }

  // Create empty proof (Guess)
  let proof_3 =
    Proof {
      piA: #"",
      piB: #"",
      piC: #"",
    }

  // * Create new Game Datum
  let game_datum_3: Data =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [1, 1, 1, 4],
      black_pegs: 0,
      white_pegs: 2,
      current_turn: 3,
      expiration_time: 600000 + 1200000 + 1200000 + 1200000,
      vk: snark_vk,
      proof: proof_3,
    }

  let game_datum_hash_3 = blake2b_256(serialise(game_datum_3))
  // * Create a new output
  let output_3: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: from_lovelace(20),
      datum: DatumHash(game_datum_hash_3),
      reference_script: None,
    }

  // * Define sigs to be included in extra_signatories Tx field.
  let signatures_3: List<Hash<Blake2b_224, VerificationKey>> =
    [#"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f"]

  // * Define validity range + 300000 (5min) to lower and upper bound
  let val_range_3: ValidityRange =
    Interval {
      lower_bound: IntervalBound {
        bound_type: Finite(1 + 300000 + 300000 + 300000),
        is_inclusive: True,
      },
      upper_bound: IntervalBound {
        bound_type: Finite(600000 + 1 + 300000 + 300000),
        is_inclusive: True,
      },
    }

  // * Transaction values wrap-up
  let tx: Transaction =
    transaction.placeholder()
      |> fn(tx) {
           Transaction {
             ..tx,
             inputs: [input_2],
             outputs: [output_3],
             extra_signatories: signatures_3,
             validity_range: val_range_3,
             datums: dict.new() |> dict.insert(key: game_datum_hash_3, value: game_datum_3, compare: bytearray.compare),
           }
         }

  // === Redeemer Definition ===
  let rdm: GameRedeemer = Guess

  let ctx: ScriptContext = ScriptContext { transaction: tx, purpose }

  mastermind(game_datum_2, rdm, ctx)
}

test turn4() {
  // === GameDatum Definition ===

  let snark_vk =
    SnarkVerificationKey {
      nPublic: 8,
      vkAlpha: #"910df641298bf37a09468eb8eefe36cd9333d2698abee298b25521570d19a04c7482b35ed0392a8275ced89cbfa44f39",
      vkBeta: #"a13e94f2ba50b23446d56fb039cbd357875acbab92ccff7471e7ca79d2748684e6c4c322dce042d33bbfb23bb22cc57d187ca5634ddad5994f1f9a2c5d9d98d8c1916d767bc9aa23de1549a12640aef88543223ac5828d0520007c140f9e8716",
      vkGamma: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      vkDelta: #"8d835235db743dab2ec2817dc2545aaf4eab5997ce1df83195733c6f7ca9619593f66d06153b294f9dc9bf4e45232534084068327fdbcc5f6bdc07bf4dd6cdd8962c75112842fd7e92b2f13da4c565c0fcff2818e34b768856dfa8041bed7b9e",
      vkAlphaBeta: [
        #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      ],
      vkIC: [
        #"aae31c7beb5a2f92b3f9be7ff278c841dc15769244c5cb81b95858fcdfad34621a86f956e1de57cb104050302cc8ae09",
        #"b721c142b4c9c1de3570dd30d6ec1fc009deef3319ecd0c681c37301eab8fa9e625d4457b3376de26c83d3a6dc63b290",
        #"b1e0a4b9324277450efd02db4b7d0451a6d556f6bd61fef2df9a7ce7fd321b27e8a0e5943967b1f82856aa87a40f17ba",
        #"ad3f4b41f48a13eceda136882dfc5cc543cab7714a0abdedf7cc85fa58b4b2c69c1a8f74bc0d89901f2a4ab717a3e412",
        #"84e0a2709079a6c2b0ce1d3e19242d7a729e19936e8a9a7297055545048d1d7d14bd62baecb8bdd6b33809368461a5c9",
        #"b33e6b2bfc9f29ef766f6167bf6b3873e073eb79a55153b1ebba15187593273bf64ef7e155d1118535bab8d16676c27e",
        #"89ce67829659a866237178e52ecbfaeba754a9db3bcc097aa230cd0af9daae18346dc51685ca4ccf650094698a7115c9",
        #"8c6420bca64925df0c00b45eba87e142b04a12f86013e78c3a97c73922910b94e0647c8d60721d5749e5f5fe739dcb28",
        #"9142ab2d492fbd93323976cc16057301f4f078b273898fbf98e2c0c6aded69f54b0beae793855599d106400de6c85947"
      ],
    }

  let proof_3 =
    Proof {
      piA: #"",
      piB: #"",
      piC: #"",
    }

  // * Create new Game Datum
  let game_datum_3 =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [1, 1, 1, 4],
      black_pegs: 0,
      white_pegs: 2,
      current_turn: 3,
      expiration_time: 600000 + 1200000 + 1200000 + 1200000,
      vk: snark_vk,
      proof: proof_3,
    }

  let game_datum_hash_3 = blake2b_256(serialise(game_datum_3))
  // === Purpose Definition ===
  let tx_id =
    TransactionId {
      hash: #"502625b54a2e6b296af30652054c88bab67c3d71124de82ed83b3006fd14e368",
    }

  // This is the UTxO of the script input to be spent.
  let script_outref = OutputReference { transaction_id: tx_id, output_index: 0 }

  let purpose: ScriptPurpose = Spend(script_outref)

  // === Transaction Definition ===
  // * UTxO of the turn 1
  let utxo_3: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: from_lovelace(20),
      datum: DatumHash(game_datum_hash_3),
      reference_script: None,
    }

  // * Take the UTxO of turn 1 as input
  // Note: This is an input that comes from the script, so it is the same that the one that is contained in Spend purpose.
  let input_3: Input = Input { output_reference: script_outref, output: utxo_3 }

  // * Create new proof 
  let proof_4: Proof = Proof {
      piA: #"81a68d6aed63ad830e02fff4cbfd6201083f4d46e5d8758077322f3de4ae7a3b01280251da823952bc16e98abb5377c8",
      piB: #"a24d1cd8bede8af638f30316695cc9880db776c7e7d54b4cf27f1483ad10c36e1ec99f113975cc80a49223d8ddd6efc709d8656db16dc1d3db65017329aa82bba4102e256380f60fa72c880a4f862049f3d2ae199ae09a496275a7b2c7c38f79",
      piC: #"a82269de78d22f8e128c9d87c132f79eb228c2caa2927557c4e090d0473d02e4bbf149a21b87a3fde01f02a768fcf76b",
    }

  // * Create new Game Datum
  let game_datum_4: Data =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [1, 1, 1, 4],
      black_pegs: 2,
      white_pegs: 0,
      current_turn: 4,
      expiration_time: 600000 + 1200000 + 1200000 + 1200000 + 1200000,
      vk: snark_vk,
      proof: proof_4,
    }

  let game_datum_hash_4 = blake2b_256(serialise(game_datum_4))
  // * Create a new output
  let output_4: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: from_lovelace(20),
      datum: DatumHash(game_datum_hash_4),
      reference_script: None,
    }

  // * Define sigs to be included in extra_signatories Tx field.
  let signatures_4: List<Hash<Blake2b_224, VerificationKey>> =
    [#"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f"]

  // * Define validity range + 300000 (5min) to lower and upper bound
  let val_range_4: ValidityRange =
    Interval {
      lower_bound: IntervalBound {
        bound_type: Finite(1 + 300000 + 300000 + 300000 + 300000),
        is_inclusive: True,
      },
      upper_bound: IntervalBound {
        bound_type: Finite(600000 + 1 + 300000 + 300000 + 300000),
        is_inclusive: True,
      },
    }

  // * Transaction values wrap-up
  let tx: Transaction =
    transaction.placeholder()
      |> fn(tx) {
           Transaction {
             ..tx,
             inputs: [input_3],
             outputs: [output_4],
             extra_signatories: signatures_4,
             validity_range: val_range_4,
             datums: dict.new() |> dict.insert(key: game_datum_hash_4, value: game_datum_4, compare: bytearray.compare),
           }
         }

  // === Redeemer Definition ===
  let rdm: GameRedeemer = Clue

  let ctx: ScriptContext = ScriptContext { transaction: tx, purpose }

  mastermind(game_datum_3, rdm, ctx)
}

test turn5() {
  // === GameDatum Definition ===

  let snark_vk =
    SnarkVerificationKey {
      nPublic: 8,
      vkAlpha: #"910df641298bf37a09468eb8eefe36cd9333d2698abee298b25521570d19a04c7482b35ed0392a8275ced89cbfa44f39",
      vkBeta: #"a13e94f2ba50b23446d56fb039cbd357875acbab92ccff7471e7ca79d2748684e6c4c322dce042d33bbfb23bb22cc57d187ca5634ddad5994f1f9a2c5d9d98d8c1916d767bc9aa23de1549a12640aef88543223ac5828d0520007c140f9e8716",
      vkGamma: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      vkDelta: #"8d835235db743dab2ec2817dc2545aaf4eab5997ce1df83195733c6f7ca9619593f66d06153b294f9dc9bf4e45232534084068327fdbcc5f6bdc07bf4dd6cdd8962c75112842fd7e92b2f13da4c565c0fcff2818e34b768856dfa8041bed7b9e",
      vkAlphaBeta: [
        #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      ],
      vkIC: [
        #"aae31c7beb5a2f92b3f9be7ff278c841dc15769244c5cb81b95858fcdfad34621a86f956e1de57cb104050302cc8ae09",
        #"b721c142b4c9c1de3570dd30d6ec1fc009deef3319ecd0c681c37301eab8fa9e625d4457b3376de26c83d3a6dc63b290",
        #"b1e0a4b9324277450efd02db4b7d0451a6d556f6bd61fef2df9a7ce7fd321b27e8a0e5943967b1f82856aa87a40f17ba",
        #"ad3f4b41f48a13eceda136882dfc5cc543cab7714a0abdedf7cc85fa58b4b2c69c1a8f74bc0d89901f2a4ab717a3e412",
        #"84e0a2709079a6c2b0ce1d3e19242d7a729e19936e8a9a7297055545048d1d7d14bd62baecb8bdd6b33809368461a5c9",
        #"b33e6b2bfc9f29ef766f6167bf6b3873e073eb79a55153b1ebba15187593273bf64ef7e155d1118535bab8d16676c27e",
        #"89ce67829659a866237178e52ecbfaeba754a9db3bcc097aa230cd0af9daae18346dc51685ca4ccf650094698a7115c9",
        #"8c6420bca64925df0c00b45eba87e142b04a12f86013e78c3a97c73922910b94e0647c8d60721d5749e5f5fe739dcb28",
        #"9142ab2d492fbd93323976cc16057301f4f078b273898fbf98e2c0c6aded69f54b0beae793855599d106400de6c85947"
      ],
    }

  // * Create new proof 
  let proof_4: Proof = Proof {
      piA: #"81a68d6aed63ad830e02fff4cbfd6201083f4d46e5d8758077322f3de4ae7a3b01280251da823952bc16e98abb5377c8",
      piB: #"a24d1cd8bede8af638f30316695cc9880db776c7e7d54b4cf27f1483ad10c36e1ec99f113975cc80a49223d8ddd6efc709d8656db16dc1d3db65017329aa82bba4102e256380f60fa72c880a4f862049f3d2ae199ae09a496275a7b2c7c38f79",
      piC: #"a82269de78d22f8e128c9d87c132f79eb228c2caa2927557c4e090d0473d02e4bbf149a21b87a3fde01f02a768fcf76b",
    }

  // * Create new Game Datum
  let game_datum_4 =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [1, 1, 1, 4],
      black_pegs: 2,
      white_pegs: 0,
      current_turn: 4,
      expiration_time: 600000 + 1200000 + 1200000 + 1200000 + 1200000,
      vk: snark_vk,
      proof: proof_4,
    }

  let game_datum_hash_4 = blake2b_256(serialise(game_datum_4))
  // === Purpose Definition ===
  let tx_id =
    TransactionId {
      hash: #"502625b54a2e6b296af30652054c88bab67c3d71124de82ed83b3006fd14e368",
    }

  // This is the UTxO of the script input to be spent.
  let script_outref = OutputReference { transaction_id: tx_id, output_index: 0 }

  let purpose: ScriptPurpose = Spend(script_outref)

  // === Transaction Definition ===
  // * UTxO of the turn 1
  let utxo_4: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: from_lovelace(20),
      datum: DatumHash(game_datum_hash_4),
      reference_script: None,
    }

  // * Take the UTxO of turn 1 as input
  // Note: This is an input that comes from the script, so it is the same that the one that is contained in Spend purpose.
  let input_4: Input = Input { output_reference: script_outref, output: utxo_4 }

  // * Create empty proof Guess

  // * Create new proof 
  let proof_5: Proof = Proof {
      piA: #"",
      piB: #"",
      piC: #"",
    }

  // * Create new Game Datum
  let game_datum_5: Data =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [1, 1, 3, 4],
      black_pegs: 2,
      white_pegs: 0,
      current_turn: 5,
      expiration_time: 600000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000,
      vk: snark_vk,
      proof: proof_5,
    }

  let game_datum_hash_5 = blake2b_256(serialise(game_datum_5))
  // * Create a new output
  let output_5: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: from_lovelace(20),
      datum: DatumHash(game_datum_hash_5),
      reference_script: None,
    }

  // * Define sigs to be included in extra_signatories Tx field.
  let signatures_5: List<Hash<Blake2b_224, VerificationKey>> =
    [#"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f"]

  // * Define validity range + 300000 (5min) to lower and upper bound
  let val_range_5: ValidityRange =
    Interval {
      lower_bound: IntervalBound {
        bound_type: Finite(1 + 300000 + 300000 + 300000 + 300000 + 300000),
        is_inclusive: True,
      },
      upper_bound: IntervalBound {
        bound_type: Finite(600000 + 1 + 300000 + 300000 + 300000 + 300000),
        is_inclusive: True,
      },
    }

  // * Transaction values wrap-up
  let tx: Transaction =
    transaction.placeholder()
      |> fn(tx) {
           Transaction {
             ..tx,
             inputs: [input_4],
             outputs: [output_5],
             extra_signatories: signatures_5,
             validity_range: val_range_5,
             datums: dict.new() |> dict.insert(key: game_datum_hash_5, value: game_datum_5, compare: bytearray.compare),
           }
         }

  // === Redeemer Definition ===
  let rdm: GameRedeemer = Guess

  let ctx: ScriptContext = ScriptContext { transaction: tx, purpose }

  mastermind(game_datum_4, rdm, ctx)
}

test turn6() {
  // === GameDatum Definition ===

  let snark_vk =
    SnarkVerificationKey {
      nPublic: 8,
      vkAlpha: #"910df641298bf37a09468eb8eefe36cd9333d2698abee298b25521570d19a04c7482b35ed0392a8275ced89cbfa44f39",
      vkBeta: #"a13e94f2ba50b23446d56fb039cbd357875acbab92ccff7471e7ca79d2748684e6c4c322dce042d33bbfb23bb22cc57d187ca5634ddad5994f1f9a2c5d9d98d8c1916d767bc9aa23de1549a12640aef88543223ac5828d0520007c140f9e8716",
      vkGamma: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      vkDelta: #"8d835235db743dab2ec2817dc2545aaf4eab5997ce1df83195733c6f7ca9619593f66d06153b294f9dc9bf4e45232534084068327fdbcc5f6bdc07bf4dd6cdd8962c75112842fd7e92b2f13da4c565c0fcff2818e34b768856dfa8041bed7b9e",
      vkAlphaBeta: [
        #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      ],
      vkIC: [
        #"aae31c7beb5a2f92b3f9be7ff278c841dc15769244c5cb81b95858fcdfad34621a86f956e1de57cb104050302cc8ae09",
        #"b721c142b4c9c1de3570dd30d6ec1fc009deef3319ecd0c681c37301eab8fa9e625d4457b3376de26c83d3a6dc63b290",
        #"b1e0a4b9324277450efd02db4b7d0451a6d556f6bd61fef2df9a7ce7fd321b27e8a0e5943967b1f82856aa87a40f17ba",
        #"ad3f4b41f48a13eceda136882dfc5cc543cab7714a0abdedf7cc85fa58b4b2c69c1a8f74bc0d89901f2a4ab717a3e412",
        #"84e0a2709079a6c2b0ce1d3e19242d7a729e19936e8a9a7297055545048d1d7d14bd62baecb8bdd6b33809368461a5c9",
        #"b33e6b2bfc9f29ef766f6167bf6b3873e073eb79a55153b1ebba15187593273bf64ef7e155d1118535bab8d16676c27e",
        #"89ce67829659a866237178e52ecbfaeba754a9db3bcc097aa230cd0af9daae18346dc51685ca4ccf650094698a7115c9",
        #"8c6420bca64925df0c00b45eba87e142b04a12f86013e78c3a97c73922910b94e0647c8d60721d5749e5f5fe739dcb28",
        #"9142ab2d492fbd93323976cc16057301f4f078b273898fbf98e2c0c6aded69f54b0beae793855599d106400de6c85947"
      ],
    }

  let proof_5 =
    Proof {
      piA: #"",
      piB: #"",
      piC: #"",
    }

  // * Create new Game Datum
  let game_datum_5 =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [1, 1, 3, 4],
      black_pegs: 2,
      white_pegs: 0,
      current_turn: 5,
      expiration_time: 600000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000,
      vk: snark_vk,
      proof: proof_5,
    }

  let game_datum_hash_5 = blake2b_256(serialise(game_datum_5))
  // === Purpose Definition ===
  let tx_id =
    TransactionId {
      hash: #"cbfa499b365a398263f8e352a1ec609c20f931d089108f7a2136521137a3c52a",
    }

  // This is the UTxO of the script input to be spent.
  let script_outref = OutputReference { transaction_id: tx_id, output_index: 0 }

  let purpose: ScriptPurpose = Spend(script_outref)

  // === Transaction Definition ===
  // * UTxO of the turn 1
  let utxo_5: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: from_lovelace(20),
      datum: DatumHash(game_datum_hash_5),
      reference_script: None,
    }

  // * Take the UTxO of turn 1 as input
  // Note: This is an input that comes from the script, so it is the same that the one that is contained in Spend purpose.
  let input_5: Input = Input { output_reference: script_outref, output: utxo_5 }

  // * Create proof 
  let proof_6 =
    Proof {
      piA: #"82d169d4f21b733c86aa39ab15e7076d237136e17493ea9102cef0277c467d47a24e6a046e537ca0a5baac62793039bb",
      piB: #"9976e719144213a044a90090573e98b97f6103d47bd0d5c26264271e853621f32f7ed0c3f76ab90f71fe7e6699e9992f114dfac4a3f50305c7f94cd4e82298e63f82a69e941c26685a52ffb8abe88ee87755e2418561ef5ba06e509e0645a249",
      piC: #"b1626dfbe3c41792412e5aef1221c1a0d6b5b90088eb3a9a8fbcdbabade123f8ccbea73b78d95fffa671d5a7a5115994",
    }

  // * Create new Game Datum
  let game_datum_6: Data =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [1, 1, 3, 4],
      black_pegs: 3,
      white_pegs: 0,
      current_turn: 6,
      expiration_time: 600000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000,
      vk: snark_vk,
      proof: proof_6,
    }

  let game_datum_hash_6 = blake2b_256(serialise(game_datum_6))
  // * Create a new output
  let output_6: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: from_lovelace(20),
      datum: DatumHash(game_datum_hash_6),
      reference_script: None,
    }

  // * Define sigs to be included in extra_signatories Tx field.
  let signatures_6: List<Hash<Blake2b_224, VerificationKey>> =
    [#"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f"]

  // * Define validity range + 300000 (5min) to lower and upper bound
  let val_range_6: ValidityRange =
    Interval {
      lower_bound: IntervalBound {
        bound_type: Finite(
          1 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000,
        ),
        is_inclusive: True,
      },
      upper_bound: IntervalBound {
        bound_type: Finite(
          600000 + 1 + 300000 + 300000 + 300000 + 300000 + 300000,
        ),
        is_inclusive: True,
      },
    }

  // * Transaction values wrap-up
  let tx: Transaction =
    transaction.placeholder()
      |> fn(tx) {
           Transaction {
             ..tx,
             inputs: [input_5],
             outputs: [output_6],
             extra_signatories: signatures_6,
             validity_range: val_range_6,
             datums: dict.new() |> dict.insert(key: game_datum_hash_6, value: game_datum_6, compare: bytearray.compare),
           }
         }

  // === Redeemer Definition ===
  let rdm: GameRedeemer = Clue

  let ctx: ScriptContext = ScriptContext { transaction: tx, purpose }

  mastermind(game_datum_5, rdm, ctx)
}

test turn7() {
  // === GameDatum Definition ===

  let snark_vk =
    SnarkVerificationKey {
      nPublic: 8,
      vkAlpha: #"910df641298bf37a09468eb8eefe36cd9333d2698abee298b25521570d19a04c7482b35ed0392a8275ced89cbfa44f39",
      vkBeta: #"a13e94f2ba50b23446d56fb039cbd357875acbab92ccff7471e7ca79d2748684e6c4c322dce042d33bbfb23bb22cc57d187ca5634ddad5994f1f9a2c5d9d98d8c1916d767bc9aa23de1549a12640aef88543223ac5828d0520007c140f9e8716",
      vkGamma: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      vkDelta: #"8d835235db743dab2ec2817dc2545aaf4eab5997ce1df83195733c6f7ca9619593f66d06153b294f9dc9bf4e45232534084068327fdbcc5f6bdc07bf4dd6cdd8962c75112842fd7e92b2f13da4c565c0fcff2818e34b768856dfa8041bed7b9e",
      vkAlphaBeta: [
        #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      ],
      vkIC: [
        #"aae31c7beb5a2f92b3f9be7ff278c841dc15769244c5cb81b95858fcdfad34621a86f956e1de57cb104050302cc8ae09",
        #"b721c142b4c9c1de3570dd30d6ec1fc009deef3319ecd0c681c37301eab8fa9e625d4457b3376de26c83d3a6dc63b290",
        #"b1e0a4b9324277450efd02db4b7d0451a6d556f6bd61fef2df9a7ce7fd321b27e8a0e5943967b1f82856aa87a40f17ba",
        #"ad3f4b41f48a13eceda136882dfc5cc543cab7714a0abdedf7cc85fa58b4b2c69c1a8f74bc0d89901f2a4ab717a3e412",
        #"84e0a2709079a6c2b0ce1d3e19242d7a729e19936e8a9a7297055545048d1d7d14bd62baecb8bdd6b33809368461a5c9",
        #"b33e6b2bfc9f29ef766f6167bf6b3873e073eb79a55153b1ebba15187593273bf64ef7e155d1118535bab8d16676c27e",
        #"89ce67829659a866237178e52ecbfaeba754a9db3bcc097aa230cd0af9daae18346dc51685ca4ccf650094698a7115c9",
        #"8c6420bca64925df0c00b45eba87e142b04a12f86013e78c3a97c73922910b94e0647c8d60721d5749e5f5fe739dcb28",
        #"9142ab2d492fbd93323976cc16057301f4f078b273898fbf98e2c0c6aded69f54b0beae793855599d106400de6c85947"
      ],
    }

  let proof_6 =
    Proof {
      piA: #"82d169d4f21b733c86aa39ab15e7076d237136e17493ea9102cef0277c467d47a24e6a046e537ca0a5baac62793039bb",
      piB: #"9976e719144213a044a90090573e98b97f6103d47bd0d5c26264271e853621f32f7ed0c3f76ab90f71fe7e6699e9992f114dfac4a3f50305c7f94cd4e82298e63f82a69e941c26685a52ffb8abe88ee87755e2418561ef5ba06e509e0645a249",
      piC: #"b1626dfbe3c41792412e5aef1221c1a0d6b5b90088eb3a9a8fbcdbabade123f8ccbea73b78d95fffa671d5a7a5115994",
    }

  // * Create new Game Datum
  let game_datum_6 =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [1, 1, 3, 4],
      black_pegs: 3,
      white_pegs: 0,
      current_turn: 6,
      expiration_time: 600000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000,
      vk: snark_vk,
      proof: proof_6,
    }

  let game_datum_hash_6 = blake2b_256(serialise(game_datum_6))
  // === Purpose Definition ===
  let tx_id =
    TransactionId {
      hash: #"c0e1c053cbc0c9eb4c6f7f6e57f5a2f4f1e90b38e91deae29d9faf307109a3c2",
    }

  // This is the UTxO of the script input to be spent.
  let script_outref = OutputReference { transaction_id: tx_id, output_index: 0 }

  let purpose: ScriptPurpose = Spend(script_outref)

  // === Transaction Definition ===
  // * UTxO of the turn 1
  let utxo_6: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: from_lovelace(20),
      datum: DatumHash(game_datum_hash_6),
      reference_script: None,
    }

  // * Take the UTxO of turn 1 as input
  // Note: This is an input that comes from the script, so it is the same that the one that is contained in Spend purpose.
  let input_6: Input = Input { output_reference: script_outref, output: utxo_6 }

  // * Create proof
  let proof_7 =
    Proof {
      piA: #"",
      piB: #"",
      piC: #"",
    }

  // * Create new Game Datum
  let game_datum_7: Data =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [1, 2, 3, 4],
      black_pegs: 3,
      white_pegs: 0,
      current_turn: 7,
      expiration_time: 600000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000,
      vk: snark_vk,
      proof: proof_7,
    }

  let game_datum_hash_7 = blake2b_256(serialise(game_datum_7))
  // * Create a new output
  let output_7: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: from_lovelace(20),
      datum: DatumHash(game_datum_hash_7),
      reference_script: None,
    }

  // * Define sigs to be included in extra_signatories Tx field.
  let signatures_7: List<Hash<Blake2b_224, VerificationKey>> =
    [#"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f"]

  // * Define validity range + 300000 (5min) to lower and upper bound
  let val_range_7: ValidityRange =
    Interval {
      lower_bound: IntervalBound {
        bound_type: Finite(
          1 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000,
        ),
        is_inclusive: True,
      },
      upper_bound: IntervalBound {
        bound_type: Finite(
          600000 + 1 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000,
        ),
        is_inclusive: True,
      },
    }

  // * Transaction values wrap-up
  let tx: Transaction =
    transaction.placeholder()
      |> fn(tx) {
           Transaction {
             ..tx,
             inputs: [input_6],
             outputs: [output_7],
             extra_signatories: signatures_7,
             validity_range: val_range_7,
             datums: dict.new() |> dict.insert(key: game_datum_hash_7, value: game_datum_7, compare: bytearray.compare),
           }
         }

  // === Redeemer Definition ===
  let rdm: GameRedeemer = Guess

  let ctx: ScriptContext = ScriptContext { transaction: tx, purpose }

  mastermind(game_datum_6, rdm, ctx)
}

test turn8() {
  // === GameDatum Definition ===

  let snark_vk =
    SnarkVerificationKey {
      nPublic: 8,
      vkAlpha: #"910df641298bf37a09468eb8eefe36cd9333d2698abee298b25521570d19a04c7482b35ed0392a8275ced89cbfa44f39",
      vkBeta: #"a13e94f2ba50b23446d56fb039cbd357875acbab92ccff7471e7ca79d2748684e6c4c322dce042d33bbfb23bb22cc57d187ca5634ddad5994f1f9a2c5d9d98d8c1916d767bc9aa23de1549a12640aef88543223ac5828d0520007c140f9e8716",
      vkGamma: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      vkDelta: #"8d835235db743dab2ec2817dc2545aaf4eab5997ce1df83195733c6f7ca9619593f66d06153b294f9dc9bf4e45232534084068327fdbcc5f6bdc07bf4dd6cdd8962c75112842fd7e92b2f13da4c565c0fcff2818e34b768856dfa8041bed7b9e",
      vkAlphaBeta: [
        #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      ],
      vkIC: [
        #"aae31c7beb5a2f92b3f9be7ff278c841dc15769244c5cb81b95858fcdfad34621a86f956e1de57cb104050302cc8ae09",
        #"b721c142b4c9c1de3570dd30d6ec1fc009deef3319ecd0c681c37301eab8fa9e625d4457b3376de26c83d3a6dc63b290",
        #"b1e0a4b9324277450efd02db4b7d0451a6d556f6bd61fef2df9a7ce7fd321b27e8a0e5943967b1f82856aa87a40f17ba",
        #"ad3f4b41f48a13eceda136882dfc5cc543cab7714a0abdedf7cc85fa58b4b2c69c1a8f74bc0d89901f2a4ab717a3e412",
        #"84e0a2709079a6c2b0ce1d3e19242d7a729e19936e8a9a7297055545048d1d7d14bd62baecb8bdd6b33809368461a5c9",
        #"b33e6b2bfc9f29ef766f6167bf6b3873e073eb79a55153b1ebba15187593273bf64ef7e155d1118535bab8d16676c27e",
        #"89ce67829659a866237178e52ecbfaeba754a9db3bcc097aa230cd0af9daae18346dc51685ca4ccf650094698a7115c9",
        #"8c6420bca64925df0c00b45eba87e142b04a12f86013e78c3a97c73922910b94e0647c8d60721d5749e5f5fe739dcb28",
        #"9142ab2d492fbd93323976cc16057301f4f078b273898fbf98e2c0c6aded69f54b0beae793855599d106400de6c85947"
      ],
    }

  let proof_7 =
    Proof {
      piA: #"",
      piB: #"",
      piC: #"",
    }

  // * Create new Game Datum
  let game_datum_7 =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [1, 2, 3, 4],
      black_pegs: 3,
      white_pegs: 0,
      current_turn: 7,
      expiration_time: 600000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000,
      vk: snark_vk,
      proof: proof_7,
    }

  let game_datum_hash_7 = blake2b_256(serialise(game_datum_7))
  // === Purpose Definition ===
  let tx_id =
    TransactionId {
      hash: #"c0e1c053cbc0c9eb4c6f7f6e57f5a2f4f1e90b38e91deae29d9faf307109a3c2",
    }

  // This is the UTxO of the script input to be spent.
  let script_outref = OutputReference { transaction_id: tx_id, output_index: 0 }

  let purpose: ScriptPurpose = Spend(script_outref)

  // === Transaction Definition ===
  // * UTxO of the turn 1
  let utxo_7: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: from_lovelace(20),
      datum: DatumHash(game_datum_hash_7),
      reference_script: None,
    }

  // * Take the UTxO of turn 1 as input
  // Note: This is an input that comes from the script, so it is the same that the one that is contained in Spend purpose.
  let input_7: Input = Input { output_reference: script_outref, output: utxo_7 }

  // * Create Proof
  let proof_8 =
    Proof {
      piA: #"ab466596ac2be62a2eedcb0d48812ab7d7a4aedbfefb8ea38c604df78e9308a63ecba88e229477f9476fc4c636786493",
      piB: #"b82893f1ff0fec3d3c11a8a4017188a7e490116c8ff06c5a5bb25b68e20d2d6778def2570418c6aec9a50df324b9d8660d41a18372e6253ea2be1508a6fad89d1324187cc57595a11c6a1c2158eb03da3f13cd006a5b243198fb7f34c611c158",
      piC: #"b7c7af9fdb7f0e98a07ee8490100d265782277fc7e8e21c51794cb1908127f1e9b9365061307f4929435e39286e65d51",
    }

  // * Create new Game Datum
  let game_datum_8: Data =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [1, 2, 3, 4],
      black_pegs: 4,
      white_pegs: 0,
      current_turn: 8,
      expiration_time: 600000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000,
      vk: snark_vk,
      proof: proof_8,
    }

  let game_datum_hash_8 = blake2b_256(serialise(game_datum_8))
  // * Create a new output
  let output_8: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: from_lovelace(20),
      datum: DatumHash(game_datum_hash_8),
      reference_script: None,
    }

  // * Define sigs to be included in extra_signatories Tx field.
  let signatures_8: List<Hash<Blake2b_224, VerificationKey>> =
    [#"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f"]

  // * Define validity range + 300000 (5min) to lower and upper bound
  let val_range_8: ValidityRange =
    Interval {
      lower_bound: IntervalBound {
        bound_type: Finite(
          1 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000,
        ),
        is_inclusive: True,
      },
      upper_bound: IntervalBound {
        bound_type: Finite(
          600000 + 1 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000,
        ),
        is_inclusive: True,
      },
    }

  // * Transaction values wrap-up
  let tx: Transaction =
    transaction.placeholder()
      |> fn(tx) {
           Transaction {
             ..tx,
             inputs: [input_7],
             outputs: [output_8],
             extra_signatories: signatures_8,
             validity_range: val_range_8,
             datums: dict.new() |> dict.insert(key: game_datum_hash_8, value: game_datum_8, compare: bytearray.compare),
           }
         }

  // === Redeemer Definition ===
  let rdm: GameRedeemer = Clue

  let ctx: ScriptContext = ScriptContext { transaction: tx, purpose }

  mastermind(game_datum_7, rdm, ctx)
}

test turn9_wins_cb() {
  // === GameDatum Definition ===

  let snark_vk =
    SnarkVerificationKey {
      nPublic: 8,
      vkAlpha: #"910df641298bf37a09468eb8eefe36cd9333d2698abee298b25521570d19a04c7482b35ed0392a8275ced89cbfa44f39",
      vkBeta: #"a13e94f2ba50b23446d56fb039cbd357875acbab92ccff7471e7ca79d2748684e6c4c322dce042d33bbfb23bb22cc57d187ca5634ddad5994f1f9a2c5d9d98d8c1916d767bc9aa23de1549a12640aef88543223ac5828d0520007c140f9e8716",
      vkGamma: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      vkDelta: #"8d835235db743dab2ec2817dc2545aaf4eab5997ce1df83195733c6f7ca9619593f66d06153b294f9dc9bf4e45232534084068327fdbcc5f6bdc07bf4dd6cdd8962c75112842fd7e92b2f13da4c565c0fcff2818e34b768856dfa8041bed7b9e",
      vkAlphaBeta: [
        #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      ],
      vkIC: [
        #"aae31c7beb5a2f92b3f9be7ff278c841dc15769244c5cb81b95858fcdfad34621a86f956e1de57cb104050302cc8ae09",
        #"b721c142b4c9c1de3570dd30d6ec1fc009deef3319ecd0c681c37301eab8fa9e625d4457b3376de26c83d3a6dc63b290",
        #"b1e0a4b9324277450efd02db4b7d0451a6d556f6bd61fef2df9a7ce7fd321b27e8a0e5943967b1f82856aa87a40f17ba",
        #"ad3f4b41f48a13eceda136882dfc5cc543cab7714a0abdedf7cc85fa58b4b2c69c1a8f74bc0d89901f2a4ab717a3e412",
        #"84e0a2709079a6c2b0ce1d3e19242d7a729e19936e8a9a7297055545048d1d7d14bd62baecb8bdd6b33809368461a5c9",
        #"b33e6b2bfc9f29ef766f6167bf6b3873e073eb79a55153b1ebba15187593273bf64ef7e155d1118535bab8d16676c27e",
        #"89ce67829659a866237178e52ecbfaeba754a9db3bcc097aa230cd0af9daae18346dc51685ca4ccf650094698a7115c9",
        #"8c6420bca64925df0c00b45eba87e142b04a12f86013e78c3a97c73922910b94e0647c8d60721d5749e5f5fe739dcb28",
        #"9142ab2d492fbd93323976cc16057301f4f078b273898fbf98e2c0c6aded69f54b0beae793855599d106400de6c85947"
      ],
    }

  let proof_8 =
    Proof {
      piA: #"8b84d092731c653b1accdda79c51e3f5d289bed7311189d927deadef0470e437e6d1d400634726512a79a015867424e3",
      piB: #"92cb1c125816e4b522c7f430a5d74a61116b6189de7b2341f040194c02f10d9ef0cf081f4029444a65ea74e69d98b1cf08d3864087d5d2dee2ed6ab102f9b78e65d341f0824341a9fc25d0ea9dacccc5d355b4eddb0057949370a19c47135b0e",
      piC: #"a4ef633c858a3ff194db50eacdf715f7296fb3d1202c54b543284e9656b69aa90f33ac0e2572d3ab847b88268dcd1f7e",
    }

  // * Create new Game Datum
  let game_datum_8 =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [1, 2, 3, 4],
      black_pegs: 4,
      white_pegs: 0,
      current_turn: 8,
      expiration_time: 600000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000,
      vk: snark_vk,
      proof: proof_8,
    }

  let game_datum_hash_8 = blake2b_256(serialise(game_datum_8))
  // === Purpose Definition ===
  let tx_id =
    TransactionId {
      hash: #"c0e1c053cbc0c9eb4c6f7f6e57f5a2f4f1e90b38e91deae29d9faf307109a3c2",
    }

  // This is the UTxO of the script input to be spent.
  let script_outref = OutputReference { transaction_id: tx_id, output_index: 0 }

  let purpose: ScriptPurpose = Spend(script_outref)

  // === Transaction Definition ===
  // * UTxO of the turn 1
  let utxo_8: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: from_lovelace(20),
      datum: DatumHash(game_datum_hash_8),
      reference_script: None,
    }

  // * Take the UTxO of turn 1 as input
  // Note: This is an input that comes from the script, so it is the same that the one that is contained in Spend purpose.
  let input_8: Input =
    Input { output_reference: script_outref, output: utxo_8 }

  // * Create a new output
  let output_9: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
        ),
        stake_credential: None,
      },
      value: from_lovelace(20),
      datum: NoDatum,
      reference_script: None,
    }

  // * Define sigs to be included in extra_signatories Tx field.
  let signatures_9: List<Hash<Blake2b_224, VerificationKey>> =
    [#"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f"]

  // * Define validity range + 300000 (5min) to lower and upper bound
  let val_range_9: ValidityRange =
    Interval {
      lower_bound: IntervalBound {
        bound_type: Finite(
          1 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000,
        ),
        is_inclusive: True,
      },
      upper_bound: IntervalBound {
        bound_type: Finite(
          600000 + 1 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000,
        ),
        is_inclusive: True,
      },
    }

  // * Transaction values wrap-up
  let tx: Transaction =
    transaction.placeholder()
      |> fn(tx) {
           Transaction {
             ..tx,
             inputs: [input_8],
             outputs: [output_9],
             extra_signatories: signatures_9,
             validity_range: val_range_9,
           }
         }

  // === Redeemer Definition ===
  let rdm: GameRedeemer = End

  let ctx: ScriptContext = ScriptContext { transaction: tx, purpose }

  mastermind(game_datum_8, rdm, ctx)
}

test turn11_wins_cm() {
  // === GameDatum Definition ===

  let snark_vk =
    SnarkVerificationKey {
      nPublic: 8,
      vkAlpha: #"910df641298bf37a09468eb8eefe36cd9333d2698abee298b25521570d19a04c7482b35ed0392a8275ced89cbfa44f39",
      vkBeta: #"a13e94f2ba50b23446d56fb039cbd357875acbab92ccff7471e7ca79d2748684e6c4c322dce042d33bbfb23bb22cc57d187ca5634ddad5994f1f9a2c5d9d98d8c1916d767bc9aa23de1549a12640aef88543223ac5828d0520007c140f9e8716",
      vkGamma: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      vkDelta: #"8d835235db743dab2ec2817dc2545aaf4eab5997ce1df83195733c6f7ca9619593f66d06153b294f9dc9bf4e45232534084068327fdbcc5f6bdc07bf4dd6cdd8962c75112842fd7e92b2f13da4c565c0fcff2818e34b768856dfa8041bed7b9e",
      vkAlphaBeta: [
        #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      ],
      vkIC: [
        #"aae31c7beb5a2f92b3f9be7ff278c841dc15769244c5cb81b95858fcdfad34621a86f956e1de57cb104050302cc8ae09",
        #"b721c142b4c9c1de3570dd30d6ec1fc009deef3319ecd0c681c37301eab8fa9e625d4457b3376de26c83d3a6dc63b290",
        #"b1e0a4b9324277450efd02db4b7d0451a6d556f6bd61fef2df9a7ce7fd321b27e8a0e5943967b1f82856aa87a40f17ba",
        #"ad3f4b41f48a13eceda136882dfc5cc543cab7714a0abdedf7cc85fa58b4b2c69c1a8f74bc0d89901f2a4ab717a3e412",
        #"84e0a2709079a6c2b0ce1d3e19242d7a729e19936e8a9a7297055545048d1d7d14bd62baecb8bdd6b33809368461a5c9",
        #"b33e6b2bfc9f29ef766f6167bf6b3873e073eb79a55153b1ebba15187593273bf64ef7e155d1118535bab8d16676c27e",
        #"89ce67829659a866237178e52ecbfaeba754a9db3bcc097aa230cd0af9daae18346dc51685ca4ccf650094698a7115c9",
        #"8c6420bca64925df0c00b45eba87e142b04a12f86013e78c3a97c73922910b94e0647c8d60721d5749e5f5fe739dcb28",
        #"9142ab2d492fbd93323976cc16057301f4f078b273898fbf98e2c0c6aded69f54b0beae793855599d106400de6c85947"
      ],
    }

  let proof_0 =
    Proof {
      piA: #"8b84d092731c653b1accdda79c51e3f5d289bed7311189d927deadef0470e437e6d1d400634726512a79a015867424e3",
      piB: #"92cb1c125816e4b522c7f430a5d74a61116b6189de7b2341f040194c02f10d9ef0cf081f4029444a65ea74e69d98b1cf08d3864087d5d2dee2ed6ab102f9b78e65d341f0824341a9fc25d0ea9dacccc5d355b4eddb0057949370a19c47135b0e",
      piC: #"a4ef633c858a3ff194db50eacdf715f7296fb3d1202c54b543284e9656b69aa90f33ac0e2572d3ab847b88268dcd1f7e",
    }

  // * Create new Game Datum
  let game_datum_10 =
    GameDatum {
      code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
      code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
      hash_solution: 391047073361247658225232481261784502922906942967577347518894619662429381081,
      guess: [1, 2, 4, 4],
      black_pegs: 3,
      white_pegs: 0,
      current_turn: 10,
      expiration_time: 600000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000,
      vk: snark_vk,
      proof: proof_0,
    }

  let game_datum_hash_10 = blake2b_256(serialise(game_datum_10))

  // === Purpose Definition ===
  let tx_id =
    TransactionId {
      hash: #"c0e1c053cbc0c9eb4c6f7f6e57f5a2f4f1e90b38e91deae29d9faf307109a3c2",
    }

  // This is the UTxO of the script input to be spent.
  let script_outref = OutputReference { transaction_id: tx_id, output_index: 0 }

  let purpose: ScriptPurpose = Spend(script_outref)

  // === Transaction Definition ===
  // * UTxO of the turn 1
  let utxo_10: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32",
        ),
        stake_credential: None,
      },
      value: from_lovelace(20),
      datum: DatumHash(game_datum_hash_10),
      reference_script: None,
    }

  // * Take the UTxO of turn 1 as input
  // Note: This is an input that comes from the script, so it is the same that the one that is contained in Spend purpose.
  let input_10: Input =
    Input { output_reference: script_outref, output: utxo_10 }

  // * Create a new output
  let output_11: Output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(
          #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
        ),
        stake_credential: None,
      },
      value: from_lovelace(20),
      datum: NoDatum,
      reference_script: None,
    }

  // * Define sigs to be included in extra_signatories Tx field.
  let signatures_11: List<Hash<Blake2b_224, VerificationKey>> =
    [#"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f"]

  // * Define validity range + 300000 (5min) to lower and upper bound
  let val_range_11: ValidityRange =
    Interval {
      lower_bound: IntervalBound {
        bound_type: Finite(
          1 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000 + 30000,
        ),
        is_inclusive: True,
      },
      upper_bound: IntervalBound {
        bound_type: Finite(
          600000 + 1 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000 + 300000 + 30000,
        ),
        is_inclusive: True,
      },
    }

  // * Transaction values wrap-up
  let tx: Transaction =
    transaction.placeholder()
      |> fn(tx) {
           Transaction {
             ..tx,
             inputs: [input_10],
             outputs: [output_11],
             extra_signatories: signatures_11,
             validity_range: val_range_11,
           }
         }

  // === Redeemer Definition ===
  let rdm: GameRedeemer = End

  let ctx: ScriptContext = ScriptContext { transaction: tx, purpose }

  mastermind(game_datum_10, rdm, ctx)
}
