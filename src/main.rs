use rand::Rng;
use sha2::{Digest, Sha256};
use std::io;
use std::time::Instant; // Import for user input
use procfs::process::Process;

const P: u128 = 23; // Prime number
const G: u128 = 5; // Generator

#[derive(Debug)]
struct SchnorrProof {
    r: u128,
    c: u128,
    s: u128,
}

/// Generates a Schnorr proof for a given secret.
fn schnorr_prove(secret: u128) -> Result<SchnorrProof, String> {
    let mut rng = rand::thread_rng();
    let k: u128 = rng.gen_range(1..P);
    let r = mod_exp(G, k, P);

    let mut hasher = Sha256::new();
    hasher.update(r.to_be_bytes());
    hasher.update(P.to_be_bytes());

    let c_bytes = hasher.finalize();
    let c = u128::from_be_bytes(
        c_bytes[..16]
            .try_into()
            .map_err(|_| "Failed to convert hash to u128")?,
    ) % P;
    let s = (k + secret * c) % (P - 1);

    Ok(SchnorrProof { r, c, s })
}

/// Verifies a Schnorr proof against a given public key.
fn schnorr_verify(proof: &SchnorrProof, public_key: u128) -> bool {
    let lhs = mod_exp(G, proof.s, P);
    let rhs = (proof.r * mod_exp(public_key, proof.c, P)) % P;
    lhs == rhs
}

/// Performs modular exponentiation.
fn mod_exp(base: u128, exp: u128, modulus: u128) -> u128 {
    let mut result = 1;
    let mut base = base % modulus;
    let mut exp = exp;

    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exp >>= 1; // Divide exp by 2
    }
    result
}

/// Logs the performance metrics of the current process.
pub fn log_performance() {
    let pid: i32 = std::process::id() as i32;
    let process = Process::new(pid).unwrap();

    if let Ok(stat) = process.stat() {
        println!(
            "Memory Usage: {} KB",
            stat.rss * 4, // Convert to KB (each page is 4 KB)
        );
    }
}

fn main() {
    let secret = loop {
        // Ask the user for the first secret
        println!("Please enter your first secret (a number):");
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");

        match input.trim().parse::<u128>() {
            Ok(num) => break num,
            Err(_) => println!("Invalid input. Please enter a valid number."),
        }
    };

    let second_secret = loop {
        // Ask the user for the second secret
        println!("Please enter your second secret (a number):");
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");

        match input.trim().parse::<u128>() {
            Ok(num) => break num,
            Err(_) => println!("Invalid input. Please enter a valid number."),
        }
    };

    let public_key = mod_exp(G, secret, P);

    println!("Generating Schnorr proof...");
    let start = Instant::now();
    match schnorr_prove(secret) {
        Ok(proof) => {
            let elapsed_prove = start.elapsed();
            println!("Proof: {:?}", proof);
            println!("Proof generated in {:.2?}", elapsed_prove);

            // Verify with the same secret
            println!("Verifying Schnorr proof with the first secret...");
            let start = Instant::now();
            let valid = schnorr_verify(&proof, public_key);
            let elapsed_verify = start.elapsed();
            println!("Proof valid: {}", valid);
            println!("Verification time: {:.2?}", elapsed_verify);

            // Check with the second secret
            let second_public_key = mod_exp(G, second_secret, P);
            let valid_with_second_secret = schnorr_verify(&proof, second_public_key);
            println!(
                "Verification with second secret valid: {}",
                valid_with_second_secret
            );
        }
        Err(e) => {
            eprintln!("Error generating proof: {}", e);
        }
    }

    // Log performance metrics
    log_performance();
}
