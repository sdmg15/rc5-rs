use std::convert::TryInto;

pub fn word_as_str(e: &[u32; 2]) -> String {
	let mut output = String::new();

    e.iter().for_each(|e| {
        for i in (0..32).step_by(8) {
            let data = (e >> i) & 0xFF;
            output.push_str(&format!("{:02X?}", data))
        }
    });

	output
}

pub fn to_words(v: &Vec<u8>) -> [u32; 2] {
    println!("{v:?}");
    let w1 = u32::from_ne_bytes(v[0..4].try_into().unwrap());
    let w2 = u32::from_ne_bytes(v[4..].try_into().unwrap());
    [w1, w2]
}