//! Pull permutations: output position j takes input position `indices[j]`.

use super::{CipherError, PositionTrace, Transform, parameter, validate_text};

/// A validated bijection of positions `0..len` with explicit direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permutation {
    indices: Vec<usize>,
}

impl Permutation {
    /// Validate a pull map. An empty map is the identity on empty messages.
    ///
    /// # Errors
    /// Rejects duplicate and out-of-range indices.
    pub fn new(indices: Vec<usize>) -> Result<Self, CipherError> {
        let mut seen = vec![false; indices.len()];
        for &index in &indices {
            let Some(slot) = seen.get_mut(index) else {
                return Err(parameter("permutation", "index outside 0..length"));
            };
            if *slot {
                return Err(parameter("permutation", "indices must not repeat"));
            }
            *slot = true;
        }
        Ok(Self { indices })
    }

    /// Read a rowwise-filled, possibly ragged grid in the supplied column order.
    ///
    /// `column_order` must permute `0..width`, where width is its length.
    /// Reverse rows means read each column bottom-to-top. Missing cells in a
    /// final short row are skipped, with no padding.
    ///
    /// # Errors
    /// Rejects zero width, invalid column order, or an unallocatable result size.
    pub fn columnar(
        length: usize,
        column_order: &[usize],
        reverse_rows: bool,
    ) -> Result<Self, CipherError> {
        if column_order.is_empty() {
            return Err(parameter("column order", "width must be positive"));
        }
        Self::new(column_order.to_vec())?;
        let width = column_order.len();
        let mut indices = Vec::new();
        indices
            .try_reserve_exact(length)
            .map_err(|_| parameter("length", "cannot allocate this many positions"))?;
        for &column in column_order {
            if column >= length {
                continue;
            }
            let last_row = (length - 1 - column) / width;
            for step in 0..=last_row {
                let row = if reverse_rows { last_row - step } else { step };
                indices.push(row * width + column);
            }
        }
        // Every occupied cell appears once: no second allocation/validation is
        // needed for this map constructed from a validated column permutation.
        Ok(Self { indices })
    }

    /// Return the exact pull map, also suitable for transporting cribs.
    #[must_use]
    pub fn indices(&self) -> &[usize] {
        &self.indices
    }

    /// Invert the map; applying the inverse restores the original order.
    #[must_use]
    pub fn inverse(&self) -> Self {
        let mut indices = vec![0; self.indices.len()];
        for (output, &input) in self.indices.iter().enumerate() {
            indices[input] = output;
        }
        Self { indices }
    }

    /// Compose in execution order: apply this map, then `next`.
    ///
    /// # Errors
    /// Rejects maps with different lengths.
    ///
    /// # Examples
    /// ```
    /// use kryptos_research::cipher::permutation::Permutation;
    /// let first = Permutation::new(vec![2, 0, 1])?;
    /// let second = Permutation::new(vec![1, 0, 2])?;
    /// assert_eq!(first.then(&second)?.apply("ABC")?.text, "ACB");
    /// # Ok::<(), kryptos_research::cipher::CipherError>(())
    /// ```
    pub fn then(&self, next: &Self) -> Result<Self, CipherError> {
        if self.indices.len() != next.indices.len() {
            return Err(CipherError::LengthMismatch {
                expected: self.indices.len(),
                actual: next.indices.len(),
            });
        }
        Ok(Self {
            indices: next
                .indices
                .iter()
                .map(|&index| self.indices[index])
                .collect(),
        })
    }

    /// Apply the pull map to a normalized message, tracing each source position.
    ///
    /// # Errors
    /// Rejects non-A–Z text or a message length different from the map's length.
    pub fn apply(&self, input: &str) -> Result<Transform, CipherError> {
        validate_text(input)?;
        if input.len() != self.indices.len() {
            return Err(CipherError::LengthMismatch {
                expected: self.indices.len(),
                actual: input.len(),
            });
        }
        let mut text = String::with_capacity(input.len());
        let trace = self
            .indices
            .iter()
            .enumerate()
            .map(|(output_index, &input_index)| {
                let letter = char::from(input.as_bytes()[input_index]);
                text.push(letter);
                PositionTrace {
                    output_index,
                    input_index,
                    input: letter,
                    output: letter,
                    input_value: None,
                    key_value: None,
                    output_value: None,
                }
            })
            .collect();
        Ok(Transform { text, trace })
    }

    /// Identify the exact map, independent of how many stages constructed it.
    #[must_use]
    pub fn canonical_id(&self) -> String {
        format!("pull-v1:{:?}", self.indices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ragged_columnar_known_answer_skips_missing_cells() {
        assert_eq!(
            Permutation::columnar(7, &[2, 0, 1], false)
                .unwrap()
                .apply("ABCDEFG")
                .unwrap()
                .text,
            "CFADGBE"
        );
    }

    #[test]
    fn ragged_bottom_to_top_known_answer_is_explicit() {
        assert_eq!(
            Permutation::columnar(7, &[0, 1, 2], true)
                .unwrap()
                .apply("ABCDEFG")
                .unwrap()
                .text,
            "GDAEBFC"
        );
    }

    #[test]
    fn narrow_and_wide_grids_preserve_single_letter_and_empty_messages() {
        for order in [vec![0], vec![2, 1, 0]] {
            for text in ["", "A"] {
                assert_eq!(
                    Permutation::columnar(text.len(), &order, false)
                        .unwrap()
                        .apply(text)
                        .unwrap()
                        .text,
                    text
                );
            }
        }
    }

    #[test]
    fn inverse_restores_all_ragged_boundaries() {
        for length in 0..=100 {
            for width in 1..=15 {
                let map =
                    Permutation::columnar(length, &(0..width).rev().collect::<Vec<_>>(), true)
                        .unwrap();
                assert_eq!(
                    map.then(&map.inverse()).unwrap().indices,
                    (0..length).collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn composition_matches_sequential_application_without_commuting_stages() {
        let first = Permutation::new(vec![2, 0, 1]).unwrap();
        let second = Permutation::new(vec![1, 0, 2]).unwrap();
        assert_eq!(
            first.then(&second).unwrap().apply("ABC").unwrap().text,
            "ACB"
        );
    }

    #[test]
    fn illegal_maps_widths_sizes_and_lengths_are_errors() {
        assert!(Permutation::new(vec![0, 0]).is_err());
        assert!(Permutation::new(vec![usize::MAX]).is_err());
        assert!(Permutation::columnar(1, &[], false).is_err());
        assert!(Permutation::columnar(usize::MAX, &[0], false).is_err());
        assert!(Permutation::new(vec![0]).unwrap().apply("AA").is_err());
        assert!(
            Permutation::new(vec![0])
                .unwrap()
                .then(&Permutation::new(vec![]).unwrap())
                .is_err()
        );
        assert!(Permutation::new(vec![0]).unwrap().apply("?").is_err());
    }
}
