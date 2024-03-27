# zk-mastermind-aiken

This is a Aiken validator that implements the Mastermind game. The aim of this project is to illustrate the use of zero-knowledge proofs, and it is part of our F10 Catalyst proposal.

Mastermind is an ideal application for zk-SNARKs, a cryptographic protocol enabling zero-knowledge proofs. This two-player game features a codemaster, who chooses a sequence of colored pegs, and a codebreaker, who aims to guess this sequence within a set number of attempts. zk-SNARKs can verify the accuracy of the codebreaker's guesses without disclosing the actual sequence, thereby preserving the secret code and integrity simultaneously throughout the game.

## Versions

There are two versions of the validator to suit different transaction construction. Each one reside in different branches of the repository:

* **Main:** In the main branch resides the inlined datum version.
* **feature/datum-hash:** In this branch resides the datum-hashed version.

## Compilation

To compile the validator use the following command: 

```sh
aiken build
```

This will create a blueprint of the validator where the compiled code can be accessed and interfaces of the data. Also the blueprint can be converted into a .plutus format with the following command.

```sh
aiken blueprint convert
```

## Execute test

Several test have been made to check the game logic. One can execute a simulation of a full game running:

```sh
aiken check -t silent -m tests/full_game
```

The game also allows winning by default, that is when an user doesn't respond to the game within a 20minutes range. This is tested with:

```sh
aiken check -t silent -m tests/win_by_default
```

Finally many attacks have been anticipated and tested. To check this run:

```sh
aiken check -t silent -m tests/attacks
```
