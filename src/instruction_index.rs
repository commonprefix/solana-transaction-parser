#[derive(Clone, Copy, Debug)]
pub struct InstructionIndex {
    pub outer_index: u8,
    pub inner_index: u8,
}

impl InstructionIndex {
    pub fn new(outer_index: u8, inner_index: u8) -> Self {
        Self {
            outer_index,
            inner_index,
        }
    }

    pub fn serialize(&self) -> String {
        format!("{}.{}", self.outer_index, self.inner_index)
    }
}
