use rc5::{ControlBlock, Rc5Trait, RC5};
mod helper;
use helper::{to_words, word_as_str};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<String>>();
    let secret = args.get(1).unwrap();
    let plaintext = args.get(2).unwrap();

    let mut ctrl = ControlBlock::default();
    ctrl.set_secret_key(secret.as_bytes().to_vec());

    let rc5 = RC5::init(ctrl);

    let plaintext = plaintext.as_bytes().to_vec();
    let w_pt = to_words(&plaintext);
    let ct = rc5.encrypt(&w_pt);

    println!("Your cipher text is {}", word_as_str(&[ct[0], ct[1]]));

    let decrypted = rc5.decrypt(&ct);

    println!(
        "Decrypted text is {}",
        word_as_str(&[decrypted[0], decrypted[1]])
    );

    Ok(())
}
