//! Decompression for PEF pattern-initialized data sections.

use anyhow::{anyhow, bail, Result};

/// Expand the contents of a PEF pattern-initialized data section.
///
/// `input` is the raw section content from the container, i.e. `packed_size` bytes starting
/// at the section's `container_offset`. The returned buffer is the expanded section, which
/// should match the section header's `unpacked_size`.
pub fn decompress(input: &[u8]) -> Result<Vec<u8>> {
    Decompressor { input, pos: 0, output: Vec::new() }.run()
}

#[derive(Debug, Clone, Copy)]
enum OpcodeKind {
    /// Write `count` zero bytes.
    Zero = 0b000,
    /// Copy `count` bytes from the input.
    BlockCopy = 0b001,
    /// Copy a `count`-byte block, then repeat it.
    RepeatedBlock = 0b010,
    /// Alternate a shared block with per-iteration blocks copied from the input.
    InterleaveRepeatBlockWithBlockCopy = 0b011,
    /// Alternate a run of zeroes with per-iteration blocks copied from the input.
    InterleaveRepeatBlockWithZero = 0b100,
}

#[derive(Debug)]
struct Opcode {
    kind: OpcodeKind,
    count: usize,
}

struct Decompressor<'a> {
    input: &'a [u8],
    pos: usize,
    output: Vec<u8>,
}

impl<'a> Decompressor<'a> {
    fn run(mut self) -> Result<Vec<u8>> {
        while self.pos < self.input.len() {
            let opcode = self.decode_opcode()?;
            self.execute(opcode)?;
        }
        Ok(self.output)
    }

    fn next_byte(&mut self) -> Result<u8> {
        let byte = *self
            .input
            .get(self.pos)
            .ok_or_else(|| anyhow!("PEF pattern data: unexpected end of section at {:#X}", self.pos))?;
        self.pos += 1;
        Ok(byte)
    }

    /// Take `count` bytes from the input and advance the cursor.
    ///
    /// The result borrows the input rather than the decompressor, so callers can keep the
    /// slice while continuing to append to the output.
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(count).filter(|&e| e <= self.input.len()).ok_or_else(|| {
            anyhow!(
                "PEF pattern data: block of {} bytes at {:#X} runs past the end of the section",
                count,
                self.pos
            )
        })?;
        let block = &self.input[self.pos..end];
        self.pos = end;
        Ok(block)
    }

    /// Read a variable-length count: seven bits per byte, high bit means "continues".
    fn read_count(&mut self) -> Result<usize> {
        let mut value: usize = 0;
        loop {
            let byte = self.next_byte()?;
            value = value
                .checked_mul(128)
                .and_then(|v| v.checked_add((byte & 0x7F) as usize))
                .ok_or_else(|| anyhow!("PEF pattern data: count at {:#X} overflows usize", self.pos))?;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
    }

    /// Reserve output space up front, turning an implausible count into an error rather
    /// than an allocation failure. Counts come straight from the file and are not trusted.
    fn reserve(&mut self, count: usize) -> Result<()> {
        self.output
            .try_reserve(count)
            .map_err(|_| anyhow!("PEF pattern data: cannot allocate {} bytes of output", count))
    }

    fn write_zeroes(&mut self, count: usize) -> Result<()> {
        self.reserve(count)?;
        self.output.resize(self.output.len() + count, 0);
        Ok(())
    }

    fn write_block(&mut self, block: &[u8]) -> Result<()> {
        self.reserve(block.len())?;
        self.output.extend_from_slice(block);
        Ok(())
    }

    /// Copy `count` bytes straight from the input to the output.
    fn copy_block(&mut self, count: usize) -> Result<()> {
        let block = self.take(count)?;
        self.write_block(block)
    }

    fn decode_opcode(&mut self) -> Result<Opcode> {
        let offset = self.pos;
        let value = self.next_byte()?;
        let kind = match value >> 5 {
            0 => OpcodeKind::Zero,
            1 => OpcodeKind::BlockCopy,
            2 => OpcodeKind::RepeatedBlock,
            3 => OpcodeKind::InterleaveRepeatBlockWithBlockCopy,
            4 => OpcodeKind::InterleaveRepeatBlockWithZero,
            other => bail!("PEF pattern data: unknown opcode {} at {:#X}", other, offset),
        };
        // A zero count in the opcode byte means the real count follows.
        let mut count = (value & 0b0001_1111) as usize;
        if count == 0 {
            count = self.read_count()?;
        }
        Ok(Opcode { kind, count })
    }

    fn execute(&mut self, opcode: Opcode) -> Result<()> {
        match opcode.kind {
            OpcodeKind::Zero => self.write_zeroes(opcode.count)?,
            OpcodeKind::BlockCopy => self.copy_block(opcode.count)?,
            OpcodeKind::RepeatedBlock => {
                // The block is written `repeat_count + 1` times in total.
                let repeat_count = self.read_count()?;
                let block = self.take(opcode.count)?;
                let total = opcode
                    .count
                    .checked_mul(repeat_count.saturating_add(1))
                    .ok_or_else(|| anyhow!("PEF pattern data: repeated block size overflows usize"))?;
                self.reserve(total)?;
                for _ in 0..=repeat_count {
                    self.output.extend_from_slice(block);
                }
            }
            OpcodeKind::InterleaveRepeatBlockWithBlockCopy => {
                // `repeat_count` copies of (shared block + a fresh block from the input),
                // then one final copy of the shared block.
                let common_size = opcode.count;
                let custom_size = self.read_count()?;
                let repeat_count = self.read_count()?;
                let common = self.take(common_size)?;
                for _ in 0..repeat_count {
                    self.write_block(common)?;
                    self.copy_block(custom_size)?;
                }
                self.write_block(common)?;
            }
            OpcodeKind::InterleaveRepeatBlockWithZero => {
                // As above, but the shared block is a run of zeroes rather than input bytes.
                let common_size = opcode.count;
                let custom_size = self.read_count()?;
                let repeat_count = self.read_count()?;
                for _ in 0..repeat_count {
                    self.write_zeroes(common_size)?;
                    self.copy_block(custom_size)?;
                }
                self.write_zeroes(common_size)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pattern-initialized section of `assets/pef/test1.pef` (section 1: 0x5E3 bytes
    /// at container offset 0xB6F0) and the contents it must expand to.
    const PACKED: &[u8] = include_bytes!("../../assets/pef/test1_pattern_packed.bin");
    const UNPACKED: &[u8] = include_bytes!("../../assets/pef/test1_pattern_unpacked.bin");

    #[test]
    fn decompresses_test1_pattern_section() {
        let out = decompress(PACKED).unwrap();
        // The section header records unpacked_size = 0x954.
        assert_eq!(out.len(), 0x954);
        assert_eq!(out.len(), UNPACKED.len());
        assert!(out == UNPACKED, "decompressed data does not match the expected contents");
    }

    // Opcode-level tests.

    #[test]
    fn zero_opcode_writes_zeroes() {
        // kind 0, count 4
        assert_eq!(decompress(&[0x04]).unwrap(), vec![0u8; 4]);
    }

    #[test]
    fn block_copy_opcode_copies_input() {
        // kind 1, count 3, followed by the three bytes
        assert_eq!(decompress(&[0x23, 0xAA, 0xBB, 0xCC]).unwrap(), vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn repeated_block_writes_repeat_count_plus_one_copies() {
        // kind 2, count 2; repeat_count 2; block AA BB -> three copies
        let out = decompress(&[0x42, 0x02, 0xAA, 0xBB]).unwrap();
        assert_eq!(out, vec![0xAA, 0xBB, 0xAA, 0xBB, 0xAA, 0xBB]);
    }

    #[test]
    fn interleave_with_block_copy_alternates_shared_and_custom() {
        // kind 3, common_size 1; custom_size 1; repeat 2; common CC; customs 11, 22
        let out = decompress(&[0x61, 0x01, 0x02, 0xCC, 0x11, 0x22]).unwrap();
        assert_eq!(out, vec![0xCC, 0x11, 0xCC, 0x22, 0xCC]);
    }

    #[test]
    fn interleave_with_zero_alternates_zeroes_and_custom() {
        // kind 4, common_size 1; custom_size 1; repeat 2; customs 11, 22.
        // The shared run is zeroes, so it is not read from the input.
        let out = decompress(&[0x81, 0x01, 0x02, 0x11, 0x22]).unwrap();
        assert_eq!(out, vec![0x00, 0x11, 0x00, 0x22, 0x00]);
    }

    #[test]
    fn zero_count_reads_variable_length_value() {
        // kind 0 with an in-opcode count of 0: the real count (200 = 0x81 0x48) follows.
        assert_eq!(decompress(&[0x00, 0x81, 0x48]).unwrap(), vec![0u8; 200]);
    }

    #[test]
    fn empty_input_produces_empty_output() {
        assert!(decompress(&[]).unwrap().is_empty());
    }

    #[test]
    fn rejects_unknown_opcode() {
        // kind 5 is not defined by the format.
        let err = decompress(&[0xA1]).unwrap_err().to_string();
        assert!(err.contains("unknown opcode"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_block_copy_running_past_end() {
        // Asks for 3 bytes but only one follows.
        let err = decompress(&[0x23, 0xAA]).unwrap_err().to_string();
        assert!(err.contains("runs past the end"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_truncated_variable_length_count() {
        // 0x81 has the continuation bit set but the input ends.
        let err = decompress(&[0x00, 0x81]).unwrap_err().to_string();
        assert!(err.contains("unexpected end of section"), "unexpected error: {err}");
    }
}
