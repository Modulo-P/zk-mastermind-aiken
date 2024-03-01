use aiken/transaction.{Transaction, TransactionId, NoDatum, ValidityRange, OutputReference, ScriptPurpose, Spend, Output,InlineDatum, Input, ScriptContext }
use aiken/transaction/credential.{Address, ScriptCredential}
use aiken/transaction/value.{from_lovelace}
use aiken/hash.{Blake2b_224, Hash}
use aiken/interval.{Interval, IntervalBound, Finite}
use mastermind.{GameDatum, GameRedeemer, Proof, SnarkVerificationKey, VerificationKey, mastermind, End}

// Code Master withdraws

test cm_withdraw () {    

    // === GameDatum Definition ===

    let snark_vk = SnarkVerificationKey {
      nPublic: 2,
      vkAlpha: #"8e3d9e248feda194cb6fa0a3b64fd2a380cb5e94836bf8148bf97ebcbb5819d9a78f63102f0293c104bcbb2f810d8eb4",
      vkBeta: #"8cd68a7186a908212680a0234d8210c20328f8fb3ce1d69c9aec9330a5802d6cfaf6d7cf3176133221c19188590cb4141874ea7bbfcb9872931e115d882c46b90c3dcbcee10062d1c9b9b0a691d7bec7d2735f06495c7f71dea210e55b2782df",
      vkGamma: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      vkDelta: #"938231fcec443fbdeb1079ff126b8f69bd8579ffe82d39923214d4345395beee60200288fa20c97ae50f3212131b6f8802af2f9f515c65af6a9a6c294c738590104376a0af44731d6699db6a286608774243f7d1dddc4605eb340e65e15060a5",
      vkAlphaBeta: [
        #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      ],
      vkIC: [
        #"b5813c90d3455acb8608fdf66e8601f24ef048f3fdf9384862d77c72cb5cddfde2b307976b1b0319c42ba985f94be60a",
        #"a41a0e6370c054be0f9acce08e97f6d5702d9daa9e9a934e8a377f553593baa1c58062adc73d63558653422d54d6f50c",
        #"8e02a87c519c3145f984d25fdf769f74fbc36626c385d4554fb4bc1d7a12cbf669d40f257023b8b3c9a31e631aa8f981",
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

    let snark_vk = SnarkVerificationKey {
      nPublic: 2,
      vkAlpha: #"8e3d9e248feda194cb6fa0a3b64fd2a380cb5e94836bf8148bf97ebcbb5819d9a78f63102f0293c104bcbb2f810d8eb4",
      vkBeta: #"8cd68a7186a908212680a0234d8210c20328f8fb3ce1d69c9aec9330a5802d6cfaf6d7cf3176133221c19188590cb4141874ea7bbfcb9872931e115d882c46b90c3dcbcee10062d1c9b9b0a691d7bec7d2735f06495c7f71dea210e55b2782df",
      vkGamma: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      vkDelta: #"938231fcec443fbdeb1079ff126b8f69bd8579ffe82d39923214d4345395beee60200288fa20c97ae50f3212131b6f8802af2f9f515c65af6a9a6c294c738590104376a0af44731d6699db6a286608774243f7d1dddc4605eb340e65e15060a5",
      vkAlphaBeta: [
        #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      ],
      vkIC: [
        #"b5813c90d3455acb8608fdf66e8601f24ef048f3fdf9384862d77c72cb5cddfde2b307976b1b0319c42ba985f94be60a",
        #"a41a0e6370c054be0f9acce08e97f6d5702d9daa9e9a934e8a377f553593baa1c58062adc73d63558653422d54d6f50c",
        #"8e02a87c519c3145f984d25fdf769f74fbc36626c385d4554fb4bc1d7a12cbf669d40f257023b8b3c9a31e631aa8f981",
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

    let snark_vk = SnarkVerificationKey {
      nPublic: 2,
      vkAlpha: #"8e3d9e248feda194cb6fa0a3b64fd2a380cb5e94836bf8148bf97ebcbb5819d9a78f63102f0293c104bcbb2f810d8eb4",
      vkBeta: #"8cd68a7186a908212680a0234d8210c20328f8fb3ce1d69c9aec9330a5802d6cfaf6d7cf3176133221c19188590cb4141874ea7bbfcb9872931e115d882c46b90c3dcbcee10062d1c9b9b0a691d7bec7d2735f06495c7f71dea210e55b2782df",
      vkGamma: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      vkDelta: #"938231fcec443fbdeb1079ff126b8f69bd8579ffe82d39923214d4345395beee60200288fa20c97ae50f3212131b6f8802af2f9f515c65af6a9a6c294c738590104376a0af44731d6699db6a286608774243f7d1dddc4605eb340e65e15060a5",
      vkAlphaBeta: [
        #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      ],
      vkIC: [
        #"b5813c90d3455acb8608fdf66e8601f24ef048f3fdf9384862d77c72cb5cddfde2b307976b1b0319c42ba985f94be60a",
        #"a41a0e6370c054be0f9acce08e97f6d5702d9daa9e9a934e8a377f553593baa1c58062adc73d63558653422d54d6f50c",
        #"8e02a87c519c3145f984d25fdf769f74fbc36626c385d4554fb4bc1d7a12cbf669d40f257023b8b3c9a31e631aa8f981",
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