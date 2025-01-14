// Implementing AES-256 from scratch

#[derive(Debug, Clone, Copy)]
pub struct State([u8; 16]);

impl State {
    pub fn new(input: &[u8]) -> Self {
        let mut state = [0u8; 16];
        state.copy_from_slice(&input[0..16]);
        State(state)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }

    // Get value at specific row and column
    fn get(&self, row: usize, col: usize) -> u8 {
        self.0[row + 4 * col]
    }

    // Set value at specific row and column
    fn set(&mut self, row: usize, col: usize, value: u8) {
        self.0[row + 4 * col] = value;
    }
}

pub struct AesOperations;

impl AesOperations {
    // S-box lookup table
    const SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ];

    /// Performs SubBytes transformation on the state
    /// Substitutes each byte in the state with its corresponding value in the S-box
    pub fn sub_bytes(state: &mut State) {
        for byte in state.as_mut_bytes() {
            *byte = Self::SBOX[*byte as usize];
        }
    }

    /// Performs ShiftRows transformation on the state
    /// Cyclically shifts the rows of the state to the left by different offsets
    pub fn shift_rows(state: &mut State) {
        let mut temp = State::new(state.as_bytes());
        
        // Row 0: no shift
        for col in 0..4 {
            state.set(0, col, temp.get(0, col));
        }
        
        // Row 1: shift left by 1
        for col in 0..4 {
            state.set(1, col, temp.get(1, (col + 1) % 4));
        }
        
        // Row 2: shift left by 2
        for col in 0..4 {
            state.set(2, col, temp.get(2, (col + 2) % 4));
        }
        
        // Row 3: shift left by 3
        for col in 0..4 {
            state.set(3, col, temp.get(3, (col + 3) % 4));
        }
    }

    /// Galois Field multiplication
    fn gmul(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        
        for _ in 0..8 {
            if b & 1 != 0 {
                p ^= a;
            }
            
            let hi_bit_set = a & 0x80 != 0;
            a <<= 1;
            
            if hi_bit_set {
                a ^= 0x1B; // AES irreducible polynomial
            }
            
            b >>= 1;
        }
        
        p
    }

    /// Performs MixColumns transformation on the state
    /// Treats each column as a polynomial over GF(2^8) and multiplies it
    /// with a fixed polynomial a(x) = {03}x^3 + {01}x^2 + {01}x + {02}
    pub fn mix_columns(state: &mut State) {
        let mut temp = State::new(state.as_bytes());
        
        for col in 0..4 {
            state.set(0, col,
                Self::gmul(0x02, temp.get(0, col)) ^
                Self::gmul(0x03, temp.get(1, col)) ^
                temp.get(2, col) ^
                temp.get(3, col)
            );
            
            state.set(1, col,
                temp.get(0, col) ^
                Self::gmul(0x02, temp.get(1, col)) ^
                Self::gmul(0x03, temp.get(2, col)) ^
                temp.get(3, col)
            );
            
            state.set(2, col,
                temp.get(0, col) ^
                temp.get(1, col) ^
                Self::gmul(0x02, temp.get(2, col)) ^
                Self::gmul(0x03, temp.get(3, col))
            );
            
            state.set(3, col,
                Self::gmul(0x03, temp.get(0, col)) ^
                temp.get(1, col) ^
                temp.get(2, col) ^
                Self::gmul(0x02, temp.get(3, col))
            );
        }
    }

    /// Performs AddRoundKey transformation on the state
    /// XORs each byte of the state with the corresponding byte of the round key
    pub fn add_round_key(state: &mut State, round_key: &[u8]) {
        for (state_byte, key_byte) in state.as_mut_bytes().iter_mut().zip(round_key.iter()) {
            *state_byte ^= key_byte;
        }
    }
}