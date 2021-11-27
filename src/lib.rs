//! A simple disassembler for [`MOSIS`], a pen and paper instruction format for teaching and
//! learning reverse engineering.
//!
//! [`MOSIS`]: https://github.com/JHUAPL/Beat-the-Machine

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

impl From<Register> for u8 {
    fn from(reg: Register) -> Self {
        reg as u8
    }
}

impl TryFrom<u8> for Register {
    type Error = MOSISError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
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
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum MOSISError {
    #[error("invalid opcode")]
    InvalidOpcode,
    #[error("invalid register")]
    InvalidRegister,
    #[error("invalid condition")]
    InvalidCondition,
}

mod opcode {
    pub const MOV: u8 = 0;
    pub const MOVI: u8 = 1;
    pub const ADD: u8 = 2;
    pub const SUB: u8 = 3;
    pub const CMP: u8 = 4;
    pub const JCC: u8 = 5;
    pub const JMP: u8 = 6;
    pub const CALL: u8 = 7;
    pub const RET: u8 = 8;
    pub const NOP: u8 = 9;
    pub const IN: u8 = 10;
    pub const OUT: u8 = 11;
    pub const MUL: u8 = 12;
}

impl Instruction {
    /// Assemble an instruction to `u16`.
    pub fn assemble(&self) -> u16 {
        use Instruction::*;
        let (a, b, c, d) = match *self {
            Mov { dst, src } => (opcode::MOV, 0u8, dst.into(), src.into()),
            Movi { dst, imm } => (opcode::MOVI, dst.into(), 0, imm),
            Add { dst, x, y } => (opcode::ADD, dst.into(), x.into(), y.into()),
            Sub { dst, x, y } => (opcode::SUB, dst.into(), x.into(), y.into()),
            Cmp { x, y } => (opcode::CMP, 0, x.into(), y.into()),
            Jcc { cond, offset } => {
                let sign = if offset.is_negative() { 1 } else { 0 };
                let val = sign << 7 | offset.abs() as u8;
                (opcode::JCC, cond as u8, 0, val)
            }
            Jmp { address } => (opcode::JMP, (address >> 8) as u8, 0, address as u8),
            Call { address } => (opcode::CALL, (address >> 8) as u8, 0, address as u8),
            Ret => (opcode::RET, 0, 0, 0),
            Nop => (opcode::NOP, 0, 0, 0),
            In { dst } => (opcode::IN, 0, 0, dst.into()),
            Out { src } => (opcode::OUT, 0, 0, src.into()),
            Mul { dst, x, y } => (opcode::MUL, dst.into(), x.into(), y.into()),
        };

        let hi = a << 4 | b;
        let lo = c << 4 | d;
        u16::from_be_bytes([hi, lo])
    }

    /// All MOSIS instructions are 16 bits, but endianness is not specified in the documentation,
    /// so disassembly simply takes a `u16` to skirt around this ambiguity.
    pub fn disassemble(inst: u16) -> Result<Self, MOSISError> {
        // opcode is always first nibble
        let opcode = ((inst & 0xf000) >> 12) as u8;

        // next nibbles are often useful
        let a = ((inst & 0x0f00) >> 8) as u8;
        let b = ((inst & 0x00f0) >> 4) as u8;
        let c = (inst & 0x000f) as u8;

        // address mask
        let address = inst & 0x0fff;

        Ok(match opcode {
            opcode::MOV => Self::Mov { dst: b.try_into()?, src: c.try_into()? },
            0b0001 => Self::Movi {
                dst: a.try_into()?,
                imm: (inst & 0x00ff) as u8,
            },
            opcode::ADD => Self::Add {
                dst: a.try_into()?,
                x: b.try_into()?,
                y: c.try_into()?,
            },
            opcode::SUB => Self::Sub {
                dst: a.try_into()?,
                x: b.try_into()?,
                y: c.try_into()?,
            },
            opcode::CMP => Self::Cmp { x: b.try_into()?, y: c.try_into()? },
            opcode::JCC => {
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
            opcode::JMP => Self::Jmp { address },
            opcode::CALL => Self::Call { address },
            opcode::RET => Self::Ret,
            opcode::NOP => Self::Nop,
            opcode::IN => Self::In { dst: c.try_into()? },
            opcode::OUT => Self::Out { src: c.try_into()? },
            opcode::MUL => Self::Mul {
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
/// let bytes = [0x2312, 0x2a34, 0x3a98, 0x3fed];
/// let mut x = linear_sweep(&bytes);
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
/// # let bytes = &[0x2312, 0x2a34, 0x3a98, 0x3fed];
/// for instruction in linear_sweep(bytes) {
///     println!("{}", instruction.unwrap());
/// }
/// ```
pub fn linear_sweep(data: &impl AsRef<[u16]>) -> LinearSweep<'_> {
    LinearSweep { data: data.as_ref() }
}

pub struct LinearSweep<'a> {
    data: &'a [u16],
}

impl Iterator for LinearSweep<'_> {
    type Item = Result<Instruction, MOSISError>;

    fn next(&mut self) -> Option<Self::Item> {
        // get the next instruction to decode
        let inst = self.data.first()?;

        // advance the data slice
        self.data = &self.data[1..];

        Some(Instruction::disassemble(*inst))
    }
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
            ($op:tt,$a:expr,$b:expr) => {{
                let a = format!("{},", $a);
                write!(f, "{:<4} {:<4} {}", stringify!($op), a, $b)
            }};
            ($op:tt,$a:expr,$b:expr,$c:expr) => {{
                let a = format!("{},", $a);
                let b = format!("{},", $b);
                write!(f, "{:<4} {:<4} {:<4} {}", stringify!($op), a, b, $c)
            }};
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
        println!();
        let bytes = &[0x23, 0x12, 0x2a, 0x34, 0x3a, 0x98, 0x3f, 0xed];
        for instruction in linear_sweep(bytes) {
            println!("{}", instruction?);
        }
        Ok(())
    }
}
