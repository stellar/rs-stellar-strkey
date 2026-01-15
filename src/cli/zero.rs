use crate::{
    ed25519, ClaimableBalance, Contract, Decoded, HashX, LiquidityPool, PreAuthTx, Strkey,
};
use clap::{Args, ValueEnum};

#[derive(Args, Debug, Clone)]
#[command()]
pub struct Cmd {
    /// Strkey type to generate the zero value for
    #[arg()]
    strkey: StrkeyType,
    /// Output format
    #[arg(long, value_enum, default_value_t)]
    output: Output,
}

#[derive(Clone, Debug, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum StrkeyType {
    PublicKeyEd25519,
    // PrivateKeyEd25519 is intentionally omitted to reduce the chance someone accidentally thinks
    // the zero value private key is safe to use as a private key.
    PreAuthTx,
    HashX,
    MuxedAccountEd25519,
    SignedPayloadEd25519,
    Contract,
    LiquidityPool,
    ClaimableBalanceV0,
}

#[derive(Clone, Debug, Default, ValueEnum)]
pub enum Output {
    #[default]
    Strkey,
    Json,
}

impl Cmd {
    pub fn run(&self) {
        let strkey = match self.strkey {
            StrkeyType::PublicKeyEd25519 => Strkey::PublicKeyEd25519(ed25519::PublicKey([0; 32])),
            StrkeyType::PreAuthTx => Strkey::PreAuthTx(PreAuthTx([0; 32])),
            StrkeyType::HashX => Strkey::HashX(HashX([0; 32])),
            StrkeyType::MuxedAccountEd25519 => Strkey::MuxedAccountEd25519(ed25519::MuxedAccount {
                ed25519: [0; 32],
                id: 0,
            }),
            StrkeyType::SignedPayloadEd25519 => {
                Strkey::SignedPayloadEd25519(ed25519::SignedPayload {
                    ed25519: [0; 32],
                    payload: ed25519::InnerPayloadBuf::new(),
                })
            }
            StrkeyType::Contract => Strkey::Contract(Contract([0; 32])),
            StrkeyType::LiquidityPool => Strkey::LiquidityPool(LiquidityPool([0; 32])),
            StrkeyType::ClaimableBalanceV0 => {
                Strkey::ClaimableBalance(ClaimableBalance::V0([0; 32]))
            }
        };
        match self.output {
            Output::Strkey => println!("{strkey}"),
            Output::Json => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&Decoded(&strkey)).unwrap()
                )
            }
        }
    }
}
