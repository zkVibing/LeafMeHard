/// SCALE codec implementation for Polkadot trie nodes

/// Circuit-optimized conditional evaluation to avoid branching
fn strict_if(pred: bool, x: Field, y: Field) -> Field {
    let pred_f = pred as Field;
    pred_f * x + (1 - pred_f) * y
}

/// Maximum bytes for length encoding (prevents unbounded loops)
global MAX_LEN_BYTES: u32 = 8;

/// SCALE compact header containing offset and decoded length
pub struct ScaleHeader {
    pub offset: u64,    // Bytes consumed by the compact encoding
    pub length: u64,    // Decoded length value
}

impl ScaleHeader {
    pub fn new(offset: u64, length: u64) -> Self {
        Self { offset, length }
    }
}

/// Decode SCALE compact length with full 4-mode support
/// Modes:
/// - 0 (00): 0 <= n < 2^6, single byte
/// - 1 (01): 2^6 <= n < 2^14, 2 bytes
/// - 2 (10): 2^14 <= n < 2^30, 4 bytes
/// - 3 (11): 2^30 <= n, variable length
pub fn decode_compact_length<let N: u32>(input: [u8; N], start_offset: u64) -> ScaleHeader {
    assert(start_offset < N as u64, "Start offset out of bounds");

    let first_byte = input[start_offset as u32];
    let mode = first_byte & 0x03;

    // Mode indicators for strict_if optimization
    let mode0 = mode == 0; // Single byte
    let mode1 = mode == 1; // 2 bytes
    let mode2 = mode == 2; // 4 bytes
    // mode3 = mode == 3 (variable length, handled as else case)

    // Calculate offset (bytes consumed)
    let offset = if mode0 {
        1
    } else if mode1 {
        2
    } else if mode2 {
        4
    } else {
        // Mode 3: 1 + (first_byte >> 2) bytes
        1 + (first_byte >> 2) as u64
    };

    // Calculate decoded length
    let length = if mode0 {
        // Mode 0: value is in upper 6 bits
        (first_byte >> 2) as u64
    } else if mode1 {
        // Mode 1: 14-bit value across 2 bytes
        decode_mode1_length(input, start_offset) as u64
    } else if mode2 {
        // Mode 2: 30-bit value across 4 bytes
        decode_mode2_length(input, start_offset) as u64
    } else {
        // Mode 3: variable length encoding
        decode_mode3_length(input, start_offset) as u64
    };

    ScaleHeader::new(offset, length)
}

/// Decode mode 1: 2-byte encoding (2^6 <= n < 2^14)
fn decode_mode1_length<let N: u32>(input: [u8; N], start_offset: u64) -> Field {
    assert(start_offset + 1 < N as u64, "Mode 1 requires 2 bytes");

    let byte0 = input[start_offset as u32];
    let byte1 = input[(start_offset + 1) as u32];

    // Remove mode bits and combine: ((byte0 >> 2) | (byte1 << 6))
    let lower = (byte0 >> 2) as Field;
    let upper = (byte1 as Field) * 64; // << 6
    lower + upper
}

/// Decode mode 2: 4-byte encoding (2^14 <= n < 2^30)
fn decode_mode2_length<let N: u32>(input: [u8; N], start_offset: u64) -> Field {
    assert(start_offset + 3 < N as u64, "Mode 2 requires 4 bytes");

    let byte0 = input[start_offset as u32];
    let byte1 = input[(start_offset + 1) as u32];
    let byte2 = input[(start_offset + 2) as u32];
    let byte3 = input[(start_offset + 3) as u32];

    // Remove mode bits and combine little-endian
    let part0 = (byte0 >> 2) as Field;
    let part1 = (byte1 as Field) * 64;     // << 6
    let part2 = (byte2 as Field) * 16384;  // << 14
    let part3 = (byte3 as Field) * 4194304; // << 22

    part0 + part1 + part2 + part3
}

/// Decode mode 3: variable length encoding (n >= 2^30)
fn decode_mode3_length<let N: u32>(input: [u8; N], start_offset: u64) -> Field {
    let first_byte = input[start_offset as u32];
    let len_bytes = (first_byte >> 2) as u64;

    assert(len_bytes <= MAX_LEN_BYTES as u64, "Length encoding too large");
    assert(start_offset + 1 + len_bytes <= N as u64, "Not enough bytes for mode 3");

    // Decode little-endian multi-byte length
    decode_multibyte_length(input, start_offset + 1, len_bytes)
}

/// Decode multi-byte length in little-endian format (circuit-optimized)
fn decode_multibyte_length<let N: u32>(input: [u8; N], start_offset: u64, len_bytes: u64) -> Field {
    let mut result = 0 as Field;
    let mut multiplier = 1 as Field;

    // Use bounded loop for circuit constraints with strict_if for efficiency
    for i in 0..MAX_LEN_BYTES {
        let should_process = (i as u64) < len_bytes;
        let byte_index = start_offset + i as u64;
        let in_bounds = byte_index < N as u64;
        let safe_to_read = should_process & in_bounds;

        let byte_val = if safe_to_read {
            input[byte_index as u32] as Field
        } else {
            0 as Field
        };

        // Only add if we should process this byte
        result = strict_if(safe_to_read, result + byte_val * multiplier, result);
        multiplier = multiplier * 256;
    }

    result
}

/// Convert bytes to nibbles for trie keys (circuit-optimized)
pub fn bytes_to_nibbles<let N: u32>(bytes: [u8; N], byte_count: u64) -> ([u8; 64], u64) {
    let mut nibbles: [u8; 64] = [0; 64];
    let mut nibble_count = 0 as u64;

    for i in 0..N {
        let should_process = (i as u64) < byte_count;
        let byte_val = strict_if(should_process, bytes[i] as Field, 0) as u8;

        // Upper nibble
        let upper_nibble = (byte_val >> 4) & 0x0F;
        nibbles[nibble_count as u32] = strict_if(should_process, upper_nibble as Field, 0) as u8;
        nibble_count = strict_if(should_process, (nibble_count + 1) as Field, nibble_count as Field) as u64;

        // Lower nibble (with bounds check)
        let can_add_lower = should_process & (nibble_count < 64);
        let lower_nibble = byte_val & 0x0F;
        nibbles[nibble_count as u32] = strict_if(can_add_lower, lower_nibble as Field, nibbles[nibble_count as u32] as Field) as u8;
        nibble_count = strict_if(can_add_lower, (nibble_count + 1) as Field, nibble_count as Field) as u64;
    }

    (nibbles, nibble_count)
}



// Test functions


#[test]
fn test_nibbles() {
    let test_bytes: [u8; 4] = [0x12, 0x34, 0, 0];
    let (nibbles, count) = bytes_to_nibbles(test_bytes, 2);

    assert(nibbles[0] == 1);
    assert(nibbles[1] == 2);
    assert(nibbles[2] == 3);
    assert(nibbles[3] == 4);
    assert(count == 4);

    // Test that we successfully converted bytes to nibbles
    assert(count == 4);
}

#[test]
fn test_decode_mode0() {
    // Test single byte decoding (value < 64)
    let data = [8, 0, 0, 0]; // 2 << 2 = 8
    let header = decode_compact_length(data, 0);
    assert(header.length == 2);
    assert(header.offset == 1);
}

#[test]
fn test_decode_mode1() {
    // Test 2-byte decoding (64 <= value < 16384)
    let data = [145, 1, 0, 0]; // 100 encoded in mode 1
    let header = decode_compact_length(data, 0);
    assert(header.length == 100);
    assert(header.offset == 2);
}

#[test]
fn test_decode_mode2() {
    // Test 4-byte decoding (16384 <= value < 1073741824)
    // Use minimum value 16384 for mode 2
    // 16384 = 0x4000, mode 2 encoding:
    // First byte: ((16384 >> 2) & 0x3F) | 0x02 = (4096 & 0x3F) | 0x02 = 0 | 2 = 2
    // Remaining: 16384 >> 6 = 256, little endian: [2, 0, 1, 0]
    let data = [2, 0, 1, 0]; // 16384 correctly encoded in mode 2
    let header = decode_compact_length(data, 0);
    assert(header.length == 16384);
    assert(header.offset == 4);
}

#[test]
fn test_decode_boundary_values() {
    // Test boundary value 63 (last single byte)
    let data63 = [252, 0, 0, 0]; // 63 << 2 = 252
    let header63 = decode_compact_length(data63, 0);
    assert(header63.length == 63);
    assert(header63.offset == 1);

    // Test boundary value 64 (first 2-byte)
    let data64 = [1, 1, 0, 0]; // 64 in mode 1 format
    let header64 = decode_compact_length(data64, 0);
    assert(header64.length == 64);
    assert(header64.offset == 2);
}
