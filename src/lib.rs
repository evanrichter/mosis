//! A simple disassembler for [`MOSIS`], a pen and paper instruction format for teaching and
//! learning reverse engineering.
//!
//! [`MOSIS`]: https://github.com/JHUAPL/Beat-the-Machine

use std::convert::{TryFrom, TryInto};
use thiserror::Error;

/// `MOSIS` general purpose registers.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[repr(u8)]
pub enum Register {
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    Ra,
    Rb,
    Rc,
    Rd,
    Re,
    Rf,
}

impl TryFrom<u16> for Register {
    type Error = MOSISError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        use Register::*;
        Ok(match value {
            0 => R0,
            1 => R1,
            2 => R2,
            3 => R3,
            4 => R4,
            5 => R5,
            6 => R6,
            7 => R7,
            8 => R8,
            9 => R9,
            10 => Ra,
            11 => Rb,
            12 => Rc,
            13 => Rd,
            14 => Re,
            15 => Rf,
            _ => return Err(MOSISError::InvalidRegister),
        })
    }
}

/// Type alias to `u16`
///
/// Addresses are used as [`Jmp`][`Instruction::Jmp`] and [`Call`][`Instruction::Call`] targets.
/// These are 16-bit aligned, so addresses are effectively a target index to jump to, within an
/// array of instructions.
pub type Address = u16;

/// `MOSIS` instruction type.
///
/// All instructions are 16-bits. The first 4 bits represent the opcode, and the remaining 12 bits
/// are used in an instruction-dependent way. Instructions have between 0 and 3 parameters. Most of
/// the instruction names are fixed, except the conditional jump instruction (Jcc).
#[derive(Debug, PartialEq, Eq)]
pub enum Instruction {
    /// Copy the contents of the `src` register to the `dst` register.
    Mov { dst: Register, src: Register },

    /// Move a number encoded in the instruction (`imm`)into the `dst` register.
    Movi { dst: Register, imm: u8 },

    /// Add two registers `x` and `y`, and store the result in the `dst` register.
    Add { dst: Register, x: Register, y: Register },

    /// Subtract register `y` from register `x`, (`x - y`), and store the result in the `dst`
    /// register.
    Sub { dst: Register, x: Register, y: Register },

    /// Compare two registers (using [`Sub`][`Instruction::Sub`]) and set the flags register. Used by
    /// [`Jcc`][`Instruction::Jcc`].
    Cmp { x: Register, y: Register },

    /// Jump if a certain condition is true (based on the result of a [`Cmp`][`Instruction::Cmp`]).
    ///
    /// The conditional jump instruction’s name can be rendered differently depending on the
    /// condition (e.g. it becomes `JLT` when checking for "less than" or `JNE` when checking for
    /// "not equal").
    ///
    /// If condition is true, jump to the offset; otherwise, execute the next instruction. The
    /// offset is an instruction count, positive or negative based on the sign bit. Offset is from
    /// the _beginning_ of the `Jcc` instruction.
    Jcc { cond: Condition, offset: i8 },

    /// Jump to a fixed [address][`Address`].
    Jmp { address: Address },

    /// Call a function at a fixed [address][`Address`].
    ///
    /// More specifically, push the address of the following instruction onto the call stack, then
    /// [`Jmp`][`Instruction::Jmp`] to the address specified.
    Call { address: Address },

    /// Return from a function.
    ///
    /// More specifically, pop the address off the call stack, and [`Jmp`][`Instruction::Jmp`]
    /// there.
    Ret,

    /// No operation. Do nothing.
    Nop,

    /// Read from external memory or device and store in `dst` register.
    In { dst: Register },

    /// Write contents of `src` register to external memory or device.
    Out { src: Register },

    /// Multiply two registers `x` and `y` and store the result in the `dst` register.
    Mul { dst: Register, x: Register, y: Register },
}

/// Condition codes for the [conditional jump][`Instruction::Jcc`] instruction.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum Condition {
    Equal,
    LessThan,
    GreaterThan,
    LessThanOrEqual,
    GreaterThanOrEqual,
    NotEqual,
}

/// Possible errors that occur when disassembling `u16` to [`Instruction`].
#[derive(Debug, PartialEq, Eq, Error)]
pub enum MOSISError {
    #[error("invalid opcode")]
    InvalidOpcode,
    #[error("invalid register")]
    InvalidRegister,
    #[error("invalid condition")]
    InvalidCondition,
}

impl Instruction {
    /// Assemble an instruction to `u16`.
    pub fn assemble(&self) -> u16 {
        use Instruction::*;
        let (a, b, c, d) = match *self {
            Mov { dst, src } => (0, 0, dst as u16, src as u16),
            Movi { dst, imm } => (1, dst as u16, 0, imm as u16),
            Add { dst, x, y } => (2, dst as u16, x as u16, y as u16),
            Sub { dst, x, y } => (3, dst as u16, x as u16, y as u16),
            Cmp { x, y } => (4, 0, x as u16, y as u16),
            Jcc { cond, offset } => {
                let sign = if offset.is_negative() { 1 } else { 0 };
                let val = sign << 7 | offset.abs() as u16;
                (5, cond as u16, 0, val)
            }
            Jmp { address } => (6, (address >> 8) as u16, 0, address as u16),
            Call { address } => (7, (address >> 8) as u16, 0, address as u16),
            Ret => (8, 0, 0, 0),
            Nop => (9, 0, 0, 0),
            In { dst } => (10, 0, 0, dst as u16),
            Out { src } => (11, 0, 0, src as u16),
            Mul { dst, x, y } => (12, dst as u16, x as u16, y as u16),
        };
        a << 12 | (b & 0xf) << 8 | c << 4 | d
    }

    /// All MOSIS instructions are 16 bits, but endianness is not specified in the documentation,
    /// so disassembly simply takes a `u16` to skirt around this ambiguity.
    pub fn disassemble(inst: u16) -> Result<Self, MOSISError> {
        // opcode is always first nibble
        let opcode = (inst & 0xf000) >> 12;

        // next nibbles are often useful
        let a = (inst & 0x0f00) >> 8;
        let b = (inst & 0x00f0) >> 4;
        let c = inst & 0x000f;

        Ok(match opcode {
            0b0000 => Self::Mov { dst: b.try_into()?, src: c.try_into()? },
            0b0001 => Self::Movi {
                dst: a.try_into()?,
                imm: (inst & 0x00ff) as u8,
            },
            0b0010 => Self::Add {
                dst: a.try_into()?,
                x: b.try_into()?,
                y: c.try_into()?,
            },
            0b0011 => Self::Sub {
                dst: a.try_into()?,
                x: b.try_into()?,
                y: c.try_into()?,
            },
            0b0100 => Self::Cmp { x: b.try_into()?, y: c.try_into()? },
            0b0101 => {
                let mut offset = (inst & 0x007f) as u8 as i8;
                if inst & 0x0080 != 0 {
                    offset = -offset;
                }
                Self::Jcc {
                    cond: match a {
                        0b0000 => Condition::Equal,
                        0b0001 => Condition::LessThan,
                        0b0010 => Condition::GreaterThan,
                        0b0011 => Condition::LessThanOrEqual,
                        0b0100 => Condition::GreaterThanOrEqual,
                        0b0101 => Condition::NotEqual,
                        _ => return Err(MOSISError::InvalidCondition),
                    },
                    offset,
                }
            }
            0b0110 => Self::Jmp { address: inst & 0x0fff },
            0b0111 => Self::Call { address: inst & 0x0fff },
            0b1000 => Self::Ret,
            0b1001 => Self::Nop,
            0b1010 => Self::In { dst: c.try_into()? },
            0b1011 => Self::Out { src: c.try_into()? },
            0b1100 => Self::Mul {
                dst: a.try_into()?,
                x: b.try_into()?,
                y: c.try_into()?,
            },
            _ => return Err(MOSISError::InvalidOpcode),
        })
    }
}

/// Iterates over a slice of bytes, performing a linear sweep disassembly to MOSIS
/// [`Instruction`]s.
///
/// Iterate over a byte slice, disassembling as big endian `u16`s, yielding [`Instruction`]s or
/// [`MOSISError`]s when disassembly fails.
///
/// # Examples
///
/// ```
/// use mosis::{linear_sweep, Instruction::*, Register::*};
///
/// let bytes = &[0x23, 0x12, 0x2a, 0x34, 0x3a, 0x98, 0x3f, 0xed];
/// let mut x = linear_sweep(bytes);
///
/// assert_eq!(x.next(), Some(Ok(Add { dst: R3, x: R1, y: R2 })));
/// assert_eq!(x.next(), Some(Ok(Add { dst: Ra, x: R3, y: R4 })));
/// assert_eq!(x.next(), Some(Ok(Sub { dst: Ra, x: R9, y: R8 })));
/// assert_eq!(x.next(), Some(Ok(Sub { dst: Rf, x: Re, y: Rd })));
/// assert_eq!(x.next(), None);
/// ```
///
/// ```
/// use mosis::linear_sweep;
///
/// # let bytes = &[0x23, 0x12, 0x2a, 0x34, 0x3a, 0x98, 0x3f, 0xed];
/// for instruction in linear_sweep(bytes) {
///     println!("{}", instruction.unwrap());
/// }
/// ```
pub fn linear_sweep<'a>(
    bytes: &'a [u8],
) -> Box<dyn Iterator<Item = Result<Instruction, MOSISError>> + 'a> {
    let iter = bytes
        // take two bytes at a time
        .chunks_exact(2)
        // assume instructions are decoded big endian
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        // map `u16`s into `Instruction`s
        .map(|mc| Instruction::disassemble(mc));
    Box::new(iter)
}

impl TryFrom<u16> for Instruction {
    type Error = MOSISError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Instruction::disassemble(value)
    }
}

impl std::fmt::Display for Register {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "R{}", *self as u8)
    }
}

impl std::fmt::Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        macro_rules! x {
            ($op:tt) => {
                write!(f, "{:<4}", stringify!($op))
            };
            ($op:tt,$a:expr) => {
                write!(f, "{:<4} {}", stringify!($op), $a)
            };
            ($op:tt,$a:expr,$b:expr) => {
                {
                    let a = format!("{},", $a);
                    write!(f, "{:<4} {:<4} {}", stringify!($op), a, $b)
                }
            };
            ($op:tt,$a:expr,$b:expr,$c:expr) => {
                {
                    let a = format!("{},", $a);
                    let b = format!("{},", $b);
                    write!(f, "{:<4} {:<4} {:<4} {}", stringify!($op), a, b, $c)
                }
            };
        }

        use Condition::*;
        use Instruction::*;

        match *self {
            Mov { dst, src } => x!(MOV, dst, src),
            Movi { dst, imm } => x!(MOVI, dst, imm),
            Add { dst, x, y } => x!(ADD, dst, x, y),
            Sub { dst, x, y } => x!(SUB, dst, x, y),
            Cmp { x, y } => x!(CMP, x, y),
            Jcc { cond, offset } => match cond {
                Equal => x!(JEQ, offset),
                LessThan => x!(JLT, offset),
                GreaterThan => x!(JGT, offset),
                LessThanOrEqual => x!(JLTE, offset),
                GreaterThanOrEqual => x!(JGTE, offset),
                NotEqual => x!(JNE, offset),
            },
            Jmp { address } => x!(JMP, address),
            Call { address } => x!(CALL, address),
            Ret => x!(RET),
            Nop => x!(NOP),
            In { dst } => x!(IN, dst),
            Out { src } => x!(OUT, src),
            Mul { dst, x, y } => x!(MUL, dst, x, y),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Condition::*;
    use Instruction::*;
    use Register::*;

    #[test]
    fn disassembly() -> Result<(), MOSISError> {
        macro_rules! assert_dis {
            ($d:expr, $i:expr) => {
                assert_eq!(Instruction::disassemble($d)?, $i);
            };
        }

        assert_dis!(0x0012, Mov { dst: R1, src: R2 });
        assert_dis!(0x0021, Mov { dst: R2, src: R1 });
        assert_dis!(0x1122, Movi { dst: R1, imm: 0x22 });
        assert_dis!(0x1b01, Movi { dst: Rb, imm: 1 });
        assert_dis!(0x2312, Add { dst: R3, x: R1, y: R2 });
        assert_dis!(0x2a34, Add { dst: Ra, x: R3, y: R4 });
        assert_dis!(0x3a98, Sub { dst: Ra, x: R9, y: R8 });
        assert_dis!(0x3fed, Sub { dst: Rf, x: Re, y: Rd });
        assert_dis!(0x4012, Cmp { x: R1, y: R2 });
        assert_dis!(0x40bc, Cmp { x: Rb, y: Rc });
        assert_dis!(0x5085, Jcc { cond: Equal, offset: -5 });
        assert_dis!(0x40ab, Cmp { x: Ra, y: Rb });
        assert_dis!(0x542a, Jcc { cond: GreaterThanOrEqual, offset: 42 });
        assert_dis!(0x61a2, Jmp { address: 0x1a2 });
        assert_dis!(0x6eab, Jmp { address: 0xeab });
        assert_dis!(0x7fce, Call { address: 0xfce });
        assert_dis!(0x7123, Call { address: 0x123 });
        assert_dis!(0x8000, Ret);
        assert_dis!(0x9000, Nop);
        assert_dis!(0xa004, In { dst: R4 });
        assert_dis!(0xa00c, In { dst: Rc });
        assert_dis!(0xb005, Out { src: R5 });
        assert_dis!(0xb00d, Out { src: Rd });
        assert_dis!(0xca98, Mul { dst: Ra, x: R9, y: R8 });
        assert_dis!(0xcfed, Mul { dst: Rf, x: Re, y: Rd });

        Ok(())
    }

    fn roundtrip(mc: u16) -> bool {
        let (inst, mc) = match Instruction::disassemble(mc) {
            // special case: force 0 offset to have positive sign
            Ok(i @ Jcc { offset: 0, .. }) => (i, mc & 0xff7f),

            // mask out the unused bits to always be zero
            Ok(i @ Nop) => (i, mc & 0xf000),
            Ok(i @ Ret) => (i, mc & 0xf000),
            Ok(i @ Mov { .. }) => (i, mc & 0xf0ff),
            Ok(i @ Cmp { .. }) => (i, mc & 0xf0ff),
            Ok(i @ In { .. }) => (i, mc & 0xf00f),
            Ok(i @ Out { .. }) => (i, mc & 0xf00f),

            // invalid instructions can't be re-assembled, so just pass
            Err(_) => return true,
            Ok(i) => (i, mc),
        };
        mc == inst.assemble()
    }

    #[test]
    fn roundtrip_bruteforce() {
        for x in 0..=u16::MAX {
            assert!(roundtrip(x));
        }
    }

    #[test]
    fn print_test() -> Result<(), MOSISError> {
        println!("");
        let bytes = &[0x23, 0x12, 0x2a, 0x34, 0x3a, 0x98, 0x3f, 0xed];
        for instruction in linear_sweep(bytes) {
            println!("{}", instruction?);
        }
        Ok(())
    }
}
