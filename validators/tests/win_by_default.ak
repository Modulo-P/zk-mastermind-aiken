use aiken/transaction.{Transaction, TransactionId, NoDatum, ValidityRange, OutputReference, ScriptPurpose, Spend, Output,InlineDatum, Input, ScriptContext }
use aiken/transaction/credential.{Address, ScriptCredential}
use aiken/transaction/value.{from_lovelace}
use aiken/hash.{Blake2b_224, Hash}
use aiken/interval.{Interval, IntervalBound, Finite}
use mastermind.{GameDatum, GameRedeemer,  VerificationKey, mastermind, End}
use ak_381/groth16.{Proof, SnarkVerificationKey}

// Code Master withdraws

test cm_withdraw () {    

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

    let proof_0  = Proof {
      piA: #"8b84d092731c653b1accdda79c51e3f5d289bed7311189d927deadef0470e437e6d1d400634726512a79a015867424e3",
      piB: #"92cb1c125816e4b522c7f430a5d74a61116b6189de7b2341f040194c02f10d9ef0cf081f4029444a65ea74e69d98b1cf08d3864087d5d2dee2ed6ab102f9b78e65d341f0824341a9fc25d0ea9dacccc5d355b4eddb0057949370a19c47135b0e",
      piC: #"a4ef633c858a3ff194db50eacdf715f7296fb3d1202c54b543284e9656b69aa90f33ac0e2572d3ab847b88268dcd1f7e",
    }

    let game_datum_0 = GameDatum {
        code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
        code_breaker: #"",
        hash_solution: 123456789,
        guess: [],
        black_pegs: 0,
        white_pegs: 0,
        current_turn: 0,
        expiration_time: 0,
        vk: snark_vk,
        proof: proof_0,
    }


    // === Purpose Definition ===

    let tx_id = TransactionId { hash: #"5e5d8ed3ae7e640a0466908d2ed26011b3e0f7dc5759c5f6790b04927fd50fd7" }

    // This is the UTxO of the script input to be spent.
    let script_outref = OutputReference { transaction_id: tx_id, output_index: 0 }

    let purpose: ScriptPurpose =  Spend(script_outref)

    // === Transaction Definition ===

    // * UTxO of the turn 0
    let utxo_0: Output = Output {
        address: Address { payment_credential: ScriptCredential(#"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32"), stake_credential: None},
        value: from_lovelace(10),
        datum: InlineDatum(game_datum_0),
        reference_script: None,
    }  

    // * Take the UTxO of turn 0 as input
    // Note: This is an input that comes from the script, so it is the same that the one that is contained in Spend purpose.
    let input_0: Input = Input { output_reference: script_outref, output: utxo_0}

    // * Create a new output
    let output_1: Output = Output {
        address: Address { payment_credential: ScriptCredential(#"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f"), stake_credential: None},
        value: from_lovelace(20),
        datum: NoDatum,
        reference_script: None,
    }

    // * Define sigs to be included in extra_signatories Tx field.
    let signatures_1: List<Hash<Blake2b_224, VerificationKey>> = [#"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f"]

    // * Define validity range + 300000 (5min) to lower and upper bound
    let val_range_1: ValidityRange = Interval
    { lower_bound:
        IntervalBound { bound_type: Finite(300000), is_inclusive: True }
    , upper_bound:
        IntervalBound { bound_type: Finite(600000), is_inclusive: True }
    }

    // * Transaction values wrap-up
    let tx: Transaction = transaction.placeholder() |> fn (tx) {
        Transaction { ..tx, inputs: [input_0,],outputs: [output_1], extra_signatories: signatures_1, validity_range: val_range_1 }
    }

    // === Redeemer Definition ===

    let rdm: GameRedeemer = End

    let ctx: ScriptContext = ScriptContext { transaction: tx, purpose: purpose}

    mastermind(game_datum_0, rdm, ctx)
}

// The CM wins by default (in turn 7)

test cm_wins_by_default() {    

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

    let proof_0  = Proof {
      piA: #"8b84d092731c653b1accdda79c51e3f5d289bed7311189d927deadef0470e437e6d1d400634726512a79a015867424e3",
      piB: #"92cb1c125816e4b522c7f430a5d74a61116b6189de7b2341f040194c02f10d9ef0cf081f4029444a65ea74e69d98b1cf08d3864087d5d2dee2ed6ab102f9b78e65d341f0824341a9fc25d0ea9dacccc5d355b4eddb0057949370a19c47135b0e",
      piC: #"a4ef633c858a3ff194db50eacdf715f7296fb3d1202c54b543284e9656b69aa90f33ac0e2572d3ab847b88268dcd1f7e",
    }

    // * Create new Game Datum
    let game_datum_6 = GameDatum {
        code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
        code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
        hash_solution: 123456789,
        guess: [1,1,3,4],
        black_pegs: 3,
        white_pegs: 0,
        current_turn: 6,
        expiration_time: 600000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000,
        vk: snark_vk,
        proof: proof_0,
    }


    // === Purpose Definition ===

    let tx_id = TransactionId { hash: #"c0e1c053cbc0c9eb4c6f7f6e57f5a2f4f1e90b38e91deae29d9faf307109a3c2" }

    // This is the UTxO of the script input to be spent.
    let script_outref = OutputReference { transaction_id: tx_id, output_index: 0 }

    let purpose: ScriptPurpose =  Spend(script_outref)

    // === Transaction Definition ===

    // * UTxO of the turn 1
    let utxo_6: Output = Output {
        address: Address { payment_credential: ScriptCredential(#"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f"), stake_credential: None},
        value: from_lovelace(20),
        datum: InlineDatum(game_datum_6),
        reference_script: None,
    }  

    // * Take the UTxO of turn 1 as input
    // Note: This is an input that comes from the script, so it is the same that the one that is contained in Spend purpose.
    let input_6: Input = Input { output_reference: script_outref, output: utxo_6}

    // * Create a new output
    let output_7: Output = Output {
        address: Address { payment_credential: ScriptCredential(#"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f"), stake_credential: None},
        value: from_lovelace(20),
        datum: NoDatum,
        reference_script: None,
    }

    // * Define sigs to be included in extra_signatories Tx field.
    let signatures_7: List<Hash<Blake2b_224, VerificationKey>> = [#"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f"]

    // * Define validity range + 300000 (5min) to lower and upper bound
    let val_range_7: ValidityRange = Interval
    { lower_bound:
        IntervalBound { bound_type: Finite(600000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1), is_inclusive: True }
    , upper_bound:
        IntervalBound { bound_type: Finite(600000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000), is_inclusive: True }
    }

    // * Transaction values wrap-up
    let tx: Transaction = transaction.placeholder() |> fn (tx) {
        Transaction { ..tx, inputs: [input_6,],outputs: [output_7], extra_signatories: signatures_7, validity_range: val_range_7 }
    }

    // === Redeemer Definition ===

    let rdm: GameRedeemer = End

    let ctx: ScriptContext = ScriptContext { transaction: tx, purpose: purpose}

    mastermind(game_datum_6, rdm, ctx)
}




// The CB wins by default (in turn 6)

test cb_wins_by_default () {    

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

    let proof_0  = Proof {
      piA: #"8b84d092731c653b1accdda79c51e3f5d289bed7311189d927deadef0470e437e6d1d400634726512a79a015867424e3",
      piB: #"92cb1c125816e4b522c7f430a5d74a61116b6189de7b2341f040194c02f10d9ef0cf081f4029444a65ea74e69d98b1cf08d3864087d5d2dee2ed6ab102f9b78e65d341f0824341a9fc25d0ea9dacccc5d355b4eddb0057949370a19c47135b0e",
      piC: #"a4ef633c858a3ff194db50eacdf715f7296fb3d1202c54b543284e9656b69aa90f33ac0e2572d3ab847b88268dcd1f7e",
    }

    // * Create new Game Datum
    let game_datum_5 = GameDatum {
        code_master: #"4aea7b7035ac699d5d639ca4a0ca9fb567afb54fb3a40e970afba01f",
        code_breaker: #"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f",
        hash_solution: 123456789,
        guess: [1,1,3,4],
        black_pegs: 2,
        white_pegs: 0,
        current_turn: 5,
        expiration_time: 600000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000,
        vk: snark_vk,
        proof: proof_0,
    }


    // === Purpose Definition ===

    let tx_id = TransactionId { hash: #"cbfa499b365a398263f8e352a1ec609c20f931d089108f7a2136521137a3c52a" }

    // This is the UTxO of the script input to be spent.
    let script_outref = OutputReference { transaction_id: tx_id, output_index: 0 }

    let purpose: ScriptPurpose =  Spend(script_outref)

    // === Transaction Definition ===

    // * UTxO of the turn 1
    let utxo_5: Output = Output {
        address: Address { payment_credential: ScriptCredential(#"b54ed6f555571f8ab586352b9defea5fb3f1d587809bbf21c4d93c32"), stake_credential: None},
        value: from_lovelace(20),
        datum: InlineDatum(game_datum_5),
        reference_script: None,
    }  

    // * Take the UTxO of turn 1 as input
    // Note: This is an input that comes from the script, so it is the same that the one that is contained in Spend purpose.
    let input_5: Input = Input { output_reference: script_outref, output: utxo_5}

    // * Create a new output
    let output_6: Output = Output {
        address: Address { payment_credential: ScriptCredential(#"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f"), stake_credential: None},
        value: from_lovelace(20),
        datum: NoDatum,
        reference_script: None,
    }

    // * Define sigs to be included in extra_signatories Tx field.
    let signatures_6: List<Hash<Blake2b_224, VerificationKey>> = [#"16ae41ffa134eca2ef5481017439cee4707d73d447f283abb1c7ec8f"]

    // * Define validity range + 300000 (5min) to lower and upper bound
    let val_range_6: ValidityRange = Interval
    { lower_bound:
        IntervalBound { bound_type: Finite(600000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 1), is_inclusive: True }
    , upper_bound:
        IntervalBound { bound_type: Finite(600000 + 1200000 + 1200000 + 1200000 + 1200000 + 1200000 + 300000), is_inclusive: True }
    }

    // * Transaction values wrap-up
    let tx: Transaction = transaction.placeholder() |> fn (tx) {
        Transaction { ..tx, inputs: [input_5,],outputs: [output_6], extra_signatories: signatures_6, validity_range: val_range_6 }
    }

    // === Redeemer Definition ===

    let rdm: GameRedeemer = End

    let ctx: ScriptContext = ScriptContext { transaction: tx, purpose: purpose}

    mastermind(game_datum_5, rdm, ctx)
}