mod helper;
use std::{fmt::Display, str::FromStr};

pub trait Rc5Trait {
    type Word;
    fn build_expanded_kt(cb: &ControlBlock) -> Vec<Self::Word>;
    fn convert_secret_key_from_bytes_to_word(cb: &ControlBlock) -> Vec<Self::Word>;
    fn mixin_secret_key(
        ctrl_block: &ControlBlock,
        expanded_kt: &mut Vec<Self::Word>,
        sec_key: &mut Vec<Self::Word>,
    );
    fn encrypt(&self, pt: &[Self::Word; 2]) -> [Self::Word; 2];
    fn decrypt(&self, ct: &[Self::Word; 2]) -> [Self::Word; 2];
}

const MAGIC_P32: u32 = 0xB7E15163;
const MAGIC_Q32: u32 = 0x9E3779B9;

#[allow(unused)]
pub struct ControlBlock {
    version: u8,
    word_size: u8,
    rounds: u8,
    secret_key_len: u8,
    secret_key: Vec<u8>, // K the b-byte secret key
}

impl Default for ControlBlock {
    fn default() -> Self {
        Self {
            version: 0x10,        // version 1.0
            word_size: 0x20,      // 32
            rounds: 0xC,          // 12
            secret_key_len: 0x10, // 16
            secret_key: vec![0; 16],
        }
    }
}

#[derive(Debug)]
pub enum Rc5Error {
    KeyLengthMismatch { expected: usize, got: usize },
    ParseHexError(String),
    InvalidWordSize,
    InvalidRoundRange,
}

impl Display for Rc5Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Self::KeyLengthMismatch { expected, got } => {
                writeln!(f, "Secret key mismatch expected {expected} got {got}")
            }
            Self::InvalidWordSize | Self::InvalidRoundRange => {
                writeln!(f, "Value should be between 0 and 255")
            }
            Self::ParseHexError(ref s) => {
                writeln!(f, "{s}")
            }
        }
    }
}

impl FromStr for ControlBlock {
    type Err = Rc5Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match hex::decode(s) {
            Err(e) => Err(Rc5Error::ParseHexError(e.to_string())),
            Ok(hex_str) => {
                let mut it = hex_str.into_iter();
                let version = it.next().unwrap();
                let word_size = it.next().unwrap();
                let rounds = it.next().unwrap();
                let secret_key_len = it.next().unwrap();
                let secret_key = it.as_slice();

                if secret_key_len as usize != secret_key.len() {
                    return Err(Rc5Error::KeyLengthMismatch {
                        expected: secret_key_len as usize,
                        got: secret_key.len(),
                    });
                }

                if ![16, 32, 64].contains(&word_size) {
                    return Err(Rc5Error::InvalidWordSize);
                }

                Ok(Self {
                    version,
                    word_size,
                    rounds,
                    secret_key_len,
                    secret_key: secret_key.to_vec(),
                })
            }
        }
    }
}

impl ControlBlock {
    pub fn new(
        version: u8,
        word_size: u8,
        rounds: u8,
        secret_key_len: u8,
        secret_key: Vec<u8>,
    ) -> Result<Self, Rc5Error> {

        if ![16, 32, 64].contains(&word_size) {
            return Err(Rc5Error::InvalidWordSize);
        }

        Ok(Self {
            version,
            word_size,
            rounds,
            secret_key_len,
            secret_key,
        })
    }

    pub fn set_secret_key(&mut self, secret_key: Vec<u8>) {
        assert_eq!(
            secret_key.len(),
            self.secret_key_len.into(),
            "Incorrect key size"
        );
        self.secret_key = secret_key;
    }
}

pub struct RC5 {
    expanded_key_table: Vec<<Self as Rc5Trait>::Word>,
    control_block: ControlBlock,
}

impl RC5 {
    pub fn init(ctrl_block: ControlBlock) -> Self {
        let mut expanded_kt = Self::build_expanded_kt(&ctrl_block);
        let mut sec_key_words = Self::convert_secret_key_from_bytes_to_word(&ctrl_block);
        Self::mixin_secret_key(&ctrl_block, &mut expanded_kt, &mut sec_key_words);

        RC5 {
            expanded_key_table: expanded_kt,
            control_block: ctrl_block,
        }
    }
}

impl Rc5Trait for RC5 {
    type Word = u32;

    fn build_expanded_kt(ctrl_block: &ControlBlock) -> Vec<Self::Word> {
        let table_size = 2 * (ctrl_block.rounds + 1);
        let mut res = Vec::with_capacity(table_size as usize);
        res.push(MAGIC_P32);

        (1..table_size).for_each(|i| {
            let lhs = res[(i - 1) as usize];
            let r: u32 = lhs.wrapping_add(MAGIC_Q32);
            res.push(r);
        });
        res
    }

    fn convert_secret_key_from_bytes_to_word(ctrl_block: &ControlBlock) -> Vec<Self::Word> {
        let larray_size = (ctrl_block.secret_key_len * 8).div_ceil(ctrl_block.word_size);
        let larray_size = larray_size.max(1);

        let mut sec_key_as_words: Vec<Self::Word> = vec![0; larray_size.into()];

        (0..ctrl_block.secret_key_len).rev().for_each(|i| {
            let u = ctrl_block.word_size.wrapping_div(8);
            let u = i.checked_div(u).unwrap();
            sec_key_as_words[u as usize] =
                (sec_key_as_words[u as usize] << 8) + ctrl_block.secret_key[i as usize] as u32;
        });
        sec_key_as_words
    }

    fn mixin_secret_key(
        ctrl_block: &ControlBlock,
        expanded_kt: &mut Vec<Self::Word>,
        sec_key: &mut Vec<Self::Word>,
    ) {
        let mut mixed_a = 0u32;
        let mut mixed_b = 0u32;
        let mut i: Self::Word = 0;
        let mut j: Self::Word = 0;
        let expanded_kt_len = (2 * (ctrl_block.rounds + 1)) as u32;
        let larray_size = (ctrl_block.secret_key_len * 8).div_ceil(ctrl_block.word_size);
        let larray_size = larray_size.max(1) as u32;

        (0..3 * expanded_kt_len).for_each(|_| {
            let mixed_key_value =
                expanded_kt[i as usize].wrapping_add(mixed_a.wrapping_add(mixed_b));
            let mixed_key_value = mixed_key_value.rotate_left(3);

            expanded_kt[i as usize] = mixed_key_value;
            mixed_a = mixed_key_value;

            let mixed_secret_value =
                sec_key[j as usize].wrapping_add(mixed_a.wrapping_add(mixed_b));
            let mixed_secret_value = mixed_secret_value.rotate_left(mixed_a.wrapping_add(mixed_b));

            sec_key[j as usize] = mixed_secret_value;
            mixed_b = mixed_secret_value;

            i = (i + 1).rem_euclid(expanded_kt_len);
            j = (j + 1).rem_euclid(larray_size);
        });
    }

    fn encrypt(&self, pt: &[Self::Word; 2]) -> [Self::Word; 2] {
        let kt = &self.expanded_key_table;
        let mut encrypted_a = pt[0].wrapping_add(kt[0]);
        let mut encrypted_b = pt[1].wrapping_add(kt[1]);

        (1..=self.control_block.rounds).for_each(|i| {
            encrypted_a = (encrypted_a ^ encrypted_b)
                .rotate_left(encrypted_b)
                .wrapping_add(kt[2 * i as usize]);

            encrypted_b = (encrypted_b ^ encrypted_a)
                .rotate_left(encrypted_a)
                .wrapping_add(kt[(2 * i + 1) as usize]);
        });

        [encrypted_a, encrypted_b]
    }

    fn decrypt(&self, ct: &[Self::Word; 2]) -> [Self::Word; 2] {
        let rounds = self.control_block.rounds;
        let kt = &self.expanded_key_table;
        let mut encrypted_a = ct[0];
        let mut encrypted_b = ct[1];

        (1..=rounds).rev().for_each(|i| {
            encrypted_b = encrypted_b
                .wrapping_sub(kt[(2 * i + 1) as usize])
                .rotate_right(encrypted_a)
                ^ encrypted_a;

            encrypted_a = encrypted_a
                .wrapping_sub(kt[(2 * i) as usize])
                .rotate_right(encrypted_b)
                ^ encrypted_b;
        });

        encrypted_b = encrypted_b.wrapping_sub(kt[1]);
        encrypted_a = encrypted_a.wrapping_sub(kt[0]);

        [encrypted_a, encrypted_b]
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::helper::{to_words, word_as_str};

    #[test]
    fn test_encrypt_from_str() {
        let cb = ControlBlock::from_str("10200C1000000000000000000000000000000000");
        let rc5 = RC5::init(cb.unwrap());

        let pt = [0u32, 0u32];
        let [c1, c2] = rc5.encrypt(&pt);
        let out = word_as_str(&[c1, c2]);

        assert_eq!(out, "21A5DBEE154B8F6D");

        let [pt1, pt2] = rc5.decrypt(&[c1, c2]);

        assert_eq!(pt[0], pt1);
        assert_eq!(pt[1], pt2);
    }

    #[test]
    fn test_encryption() {
        let ctrl = ControlBlock::default();
        let rc5 = RC5::init(ctrl);

        let pt = [0u32, 0u32];
        let [c1, c2] = rc5.encrypt(&pt);
        let out = word_as_str(&[c1, c2]);

        assert_eq!(out, "21A5DBEE154B8F6D");

        let [pt1, pt2] = rc5.decrypt(&[c1, c2]);

        assert_eq!(pt[0], pt1);
        assert_eq!(pt[1], pt2);
    }

    #[test]
    fn test_encryption2() {
        let mut ctrl = ControlBlock::default();
        let secret_key = vec![
            0x91, 0x5F, 0x46, 0x19, 0xBE, 0x41, 0xB2, 0x51, 0x63, 0x55, 0xA5, 0x01, 0x10, 0xA9,
            0xCE, 0x91,
        ];
        ctrl.set_secret_key(secret_key);

        let rc5 = RC5::init(ctrl);

        let pt = [4007372065u32, 1838107413u32];
        let [c1, c2] = rc5.encrypt(&pt);
        let out = helper::word_as_str(&[c1, c2]);

        assert_eq!(out, "F7C013AC5B2B8952");

        let [pt1, pt2] = rc5.decrypt(&[c1, c2]);

        assert_eq!(pt[0], pt1);
        assert_eq!(pt[1], pt2);
    }

    #[test]
    fn test_encryption3() {
        let mut ctrl = ControlBlock::default();
        let secret_key = vec![
            0x78, 0x33, 0x48, 0xE7, 0x5A, 0xEB, 0x0F, 0x2F, 0xD7, 0xB1, 0x69, 0xBB, 0x8D, 0xC1,
            0x67, 0x87,
        ];
        ctrl.set_secret_key(secret_key);

        let rc5 = RC5::init(ctrl);

        let pt = [2886975735, 1384721243];
        let [c1, c2] = rc5.encrypt(&pt);
        let out = word_as_str(&[c1, c2]);

        assert_eq!(out, "2F42B3B70369FC92");

        let [pt1, pt2] = rc5.decrypt(&[c1, c2]);

        assert_eq!(pt[0], pt1);
        assert_eq!(pt[1], pt2);
    }

    #[test]
    fn test_encryption4() {
        let mut ctrl = ControlBlock::default();
        let secret_key = vec![
            0xDC, 0x49, 0xDB, 0x13, 0x75, 0xA5, 0x58, 0x4F, 0x64, 0x85, 0xB4, 0x13, 0xB5, 0xF1,
            0x2B, 0xAF,
        ];
        ctrl.set_secret_key(secret_key);

        let rc5 = RC5::init(ctrl);

        let pt = [3081978415, 2466015491];
        let [c1, c2] = rc5.encrypt(&pt);
        let out = word_as_str(&[c1, c2]);

        assert_eq!(out, "65C178B284D197CC");

        let [pt1, pt2] = rc5.decrypt(&[c1, c2]);

        assert_eq!(pt[0], pt1);
        assert_eq!(pt[1], pt2);
    }

    #[test]
    fn test_encryption5() {
        let mut ctrl = ControlBlock::default();
        let secret_key = vec![
            0x52, 0x69, 0xF1, 0x49, 0xD4, 0x1B, 0xA0, 0x15, 0x24, 0x97, 0x57, 0x4D, 0x7F, 0x15,
            0x31, 0x25,
        ];
        ctrl.set_secret_key(secret_key);

        let rc5 = RC5::init(ctrl);

        let pt = [2994258277, 3432501636];
        let [c1, c2] = rc5.encrypt(&pt);
        let out = word_as_str(&[c1, c2]);

        assert_eq!(out, "EB44E415DA319824");

        let [pt1, pt2] = rc5.decrypt(&[c1, c2]);

        assert_eq!(pt[0], pt1);
        assert_eq!(pt[1], pt2);
    }

    #[test]
    fn encode_a() {
        let mut ctrl = ControlBlock::default();
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        ctrl.set_secret_key(key);

        let rc5 = RC5::init(ctrl);

        let pt = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];

        let [plaintext1, plaintext2] = to_words(&pt);
        let res = rc5.encrypt(&[plaintext1, plaintext2]);

        let [ct1, ct2] = to_words(&ct);

        assert_eq!(ct1, res[0]);
        assert_eq!(ct2, res[1]);
    }

    #[test]
    fn encode_b() {
        let mut ctrl = ControlBlock::default();
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        ctrl.set_secret_key(key);

        let rc5 = RC5::init(ctrl);

        let pt = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let ct = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];

        let [plaintext1, plaintext2] = to_words(&pt);

        let res = rc5.encrypt(&[plaintext1, plaintext2]);

        let [ct1, ct2] = to_words(&ct);

        assert_eq!(ct1, res[0]);
        assert_eq!(ct2, res[1]);
    }

    #[test]
    fn decode_a() {
        let mut ctrl = ControlBlock::default();

        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        ctrl.set_secret_key(key);

        let rc5 = RC5::init(ctrl);

        let pt = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
        let ct = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

        let [plaintext1, plaintext2] = to_words(&pt);
        let [ct1, ct2] = to_words(&ct);

        let res = rc5.decrypt(&[ct1, ct2]);

        assert_eq!(plaintext1, res[0]);
        assert_eq!(plaintext2, res[1]);
    }

    #[test]
    fn decode_b() {
        let mut ctrl = ControlBlock::default();

        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        ctrl.set_secret_key(key);

        let pt = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let ct = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];

        let rc5 = RC5::init(ctrl);

        let [plaintext1, plaintext2] = to_words(&pt);
        let [ct1, ct2] = to_words(&ct);

        let res = rc5.decrypt(&[ct1, ct2]);

        assert_eq!(plaintext1, res[0]);
        assert_eq!(plaintext2, res[1]);
    }
}
