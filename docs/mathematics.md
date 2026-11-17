# CLEFIA-128 Mathematical Specification and Traceability

This document maps each implemented cryptographic component in `src/clefia/` to its authoritative specification in **RFC 6114** (*The 128-Bit Blockcipher CLEFIA*, Katagi & Moriai, March 2011) and **Sony's CLEFIA Specification v1.0** (June 2007).

---

## 1. Bit and Word Conventions (CR-01)

- **Reference:** RFC 6114 Section 2 (*Notations*), Section 5.1 (*Encryption/Decryption*), Section 6.1 (*DoubleSwap Function*).
- **Module:** `src/clefia/functions.py` (`bytes_to_words128`, `words128_to_bytes`, `word_to_bytes`, `bytes_to_word`, `words_to_int128`, `int128_to_words`).
- **Representation:**
  - CLEFIA-128 operates on 128-bit (16-byte) plaintext/ciphertext blocks and 128-bit (16-byte) keys.
  - A 16-byte block $B = b_0 \| b_1 \| \dots \| b_{15}$ is parsed in **big-endian (MSB-first)** order into four 32-bit unsigned words $(W_0, W_1, W_2, W_3)$, where $W_0$ holds bytes $b_0 \dots b_3$ and $b_0$ is the most significant byte.
  - Within a 128-bit string $X$, bit $0$ is the **most significant bit (MSB)** and bit $127$ is the **least significant bit (LSB)**.
  - Within an 8-bit element of $\mathrm{GF}(2^8)$, bit $7$ ($0\mathrm{x}80$) is the coefficient of $z^7$ and bit $0$ ($0\mathrm{x}01$) is the constant term $1$.
  - Inputs with invalid length (anything other than 16 bytes for blocks/keys) or out-of-range words raise `ValueError` or `TypeError` explicitly rather than silently truncating or padding.

---

## 2. Finite Field Arithmetic and Diffusion Matrices (CR-02, CR-06)

- **Reference:** RFC 6114 Section 4.4 (*Diffusion Matrices*) and Section 6.6 (*Constant Values*).
- **Module:** `src/clefia/field.py` (`gf_mul8`, `gf_mul16`, `gf_inv16`, `mul_m0`, `mul_m1`, `M0`, `M1`).
- **Block-data field $\mathrm{GF}(2^8)$:**
  - Defined as $\mathrm{GF}(2)[z] / (p_8(z))$ using the lexicographically first primitive polynomial:
    $$p_8(z) = z^8 + z^4 + z^3 + z^2 + 1 \quad (0\mathrm{x}11\mathrm{D}).$$
  - Field addition is bitwise XOR ($\oplus$); multiplication `gf_mul8(a, b)` performs shift-and-XOR with reduction by $0\mathrm{x}1\mathrm{D}$ when the $z^7$ term overflows.
- **Diffusion matrices $M_0, M_1 \in \mathrm{GF}(2^8)^{4\times 4}$:**
  $$M_0 = \begin{bmatrix} 01 & 02 & 04 & 06 \\ 02 & 01 & 06 & 04 \\ 04 & 06 & 01 & 02 \\ 06 & 04 & 02 & 01 \end{bmatrix}, \qquad
    M_1 = \begin{bmatrix} 01 & 08 & 02 & 0\mathrm{a} \\ 08 & 01 & 0\mathrm{a} & 02 \\ 02 & 0\mathrm{a} & 01 & 08 \\ 0\mathrm{a} & 02 & 08 & 01 \end{bmatrix}.$$
  - All entries are hexadecimal encodings of polynomials in $\mathrm{GF}(2^8)$ (e.g., $0\mathrm{x}02 \equiv z$, $0\mathrm{x}0\mathrm{a} \equiv z^3 + z$).
  - Both matrices are involutory ($M_0^2 = M_1^2 = I$) and Maximum Distance Separable (MDS) with differential/linear branch number $5$.
- **Key-schedule constant field $\mathrm{GF}(2^{16})$:**
  - Defined as $\mathrm{GF}(2)[z] / (p_{16}(z))$ with primitive polynomial:
    $$p_{16}(z) = z^{16} + z^{15} + z^{13} + z^{11} + z^5 + z^4 + 1 \quad (0\mathrm{x}1\mathrm{A}831).$$

---

## 3. Nonlinear S-Boxes $S_0$ and $S_1$ (CR-03)

- **Reference:** RFC 6114 Section 4.3 (*S-Boxes*, Tables 1 and 2); Sony CLEFIA Specification v1.0, Section 4.3.
- **Module:** `src/clefia/sboxes.py` (`S0`, `S1`, `s0`, `s1`).
- **Attribution:** The 256-entry lookup tables `S0` and `S1` in `src/clefia/sboxes.py` are copied directly from **RFC 6114, Section 4.3, Tables 1 and 2** (Sony Corporation).
- **Indexing:** For an 8-bit byte $x$, the upper nibble $(x \gg 4)$ selects the row and the lower nibble $(x \mathbin{\&} 0\mathrm{x}0\mathrm{F})$ selects the column, matching row-major tuple indexing `S0[x]` and `S1[x]`. Both $S_0$ and $S_1$ are bijections on $\{0, \dots, 255\}$.

---

## 4. Round Functions $F_0$ and $F_1$ (CR-04, CR-05)

- **Reference:** RFC 6114 Section 4.2 (*F-Functions*).
- **Module:** `src/clefia/functions.py` (`F0`, `F1`).
- **Definitions:** Given 32-bit round key $RK$ and 32-bit branch word $x$:
  1. Compute $T = RK \oplus x = T_0 \| T_1 \| T_2 \| T_3$ ($T_k \in \{0, \dots, 255\}$, MSB first).
  2. Substitution and matrix diffusion:
     - $F_0(RK, x) = M_0 \cdot (S_0(T_0), S_1(T_1), S_0(T_2), S_1(T_3))^\top$
     - $F_1(RK, x) = M_1 \cdot (S_1(T_0), S_0(T_1), S_1(T_2), S_0(T_3))^\top$
  3. Pack the resulting 4 bytes back into a big-endian 32-bit word.

---

## 5. Generalized Feistel Network $\mathrm{GFN}_{4,r}$ and $\mathrm{GFN}^{-1}_{4,r}$ (CR-07)

- **Reference:** RFC 6114 Section 4.1 (*$\mathrm{GFN}_{d,r}$*).
- **Module:** `src/clefia/gfn.py` (`gfn4`, `gfn4_inv`).
- **Forward $\mathrm{GFN}_{4,r}(RK_0, \dots, RK_{2r-1}, X_0, X_1, X_2, X_3)$:**
  - Initialize $(T_0, T_1, T_2, T_3) \leftarrow (X_0, X_1, X_2, X_3)$.
  - For $i = 0, \dots, r-1$:
    $$T_1 \leftarrow T_1 \oplus F_0(RK_{2i}, T_0), \qquad T_3 \leftarrow T_3 \oplus F_1(RK_{2i+1}, T_2),$$
    $$(T_0, T_1, T_2, T_3) \leftarrow (T_1, T_2, T_3, T_0).$$
  - Output adjustment (undoes the final left rotation): $(Y_0, Y_1, Y_2, Y_3) \leftarrow (T_3, T_0, T_1, T_2)$.
- **Inverse $\mathrm{GFN}^{-1}_{4,r}(RK_0, \dots, RK_{2r-1}, X_0, X_1, X_2, X_3)$:**
  - Reverses round-key pair order $(RK_{2(r-i)-2}, RK_{2(r-i)-1})$ and applies right branch rotation $(T_3, T_0, T_1, T_2)$ each round, finishing with $(T_1, T_2, T_3, T_0)$.

---

## 6. DoubleSwap Permutation $\Sigma$ (CR-08)

- **Reference:** RFC 6114 Section 6.1 (*DoubleSwap Function*).
- **Module:** `src/clefia/functions.py` (`double_swap`, `double_swap_words`).
- **Definition:** For a 128-bit state $X$ with bit $0$ as MSB and bit $127$ as LSB:
  $$\Sigma(X) = X[7\text{--}63] \mathbin{\|} X[121\text{--}127] \mathbin{\|} X[0\text{--}6] \mathbin{\|} X[64\text{--}120].$$
- This is an exact 128-bit non-uniform bit permutation (distinct from a simple cyclic rotation of 128 bits) used to update the intermediate key $L$ between round-key extraction steps.

---

## 7. Key Schedule Constants and CLEFIA-128 Key Schedule (CR-09, CR-10)

- **Reference:** RFC 6114 Section 6.2, Section 6.3 (*Key Scheduling for a 128-Bit Key*), and Section 6.6 (*Constant Values*).
- **Modules:** `src/clefia/constants.py` (`T_128`, `CON_128`), `src/clefia/key_schedule.py` (`key_schedule_128`, `derive_intermediate_l`).
- **Constant generation:**
  - Initial 16-bit seed $T_{128}[0] = \mathrm{IV}_{128} = 0\mathrm{x}428\mathrm{a}$, with $P_{16} = 0\mathrm{x}\mathrm{b}7\mathrm{e}1$ and $Q_{16} = 0\mathrm{x}243\mathrm{f}$.
  - For $i = 0, \dots, 29$:
    $$\mathrm{CON}_{128}[2i] = (T_{128}[i] \oplus P_{16}) \mathbin{\|} (\sim T_{128}[i] \lll_{16} 1),$$
    $$\mathrm{CON}_{128}[2i+1] = (\sim T_{128}[i] \oplus Q_{16}) \mathbin{\|} (T_{128}[i] \lll_{16} 8),$$
    $$T_{128}[i+1] = T_{128}[i] \cdot (0\mathrm{x}0002^{-1}) \pmod{0\mathrm{x}1\mathrm{A}831}.$$
- **Key expansion (`key_schedule_128`):**
  1. Compute intermediate key $L \leftarrow \mathrm{GFN}_{4,12}(\mathrm{CON}_{128}[0\dots 23], K_0, K_1, K_2, K_3)$.
  2. Assign whitening keys $(WK_0, WK_1, WK_2, WK_3) \leftarrow (K_0, K_1, K_2, K_3)$.
  3. For $i = 0, \dots, 8$:
     - $T \leftarrow L \oplus (\mathrm{CON}_{128}[24+4i] \| \mathrm{CON}_{128}[24+4i+1] \| \mathrm{CON}_{128}[24+4i+2] \| \mathrm{CON}_{128}[24+4i+3])$,
     - $L \leftarrow \Sigma(L)$,
     - If $i$ is odd, $T \leftarrow T \oplus K$,
     - $(RK_{4i}, RK_{4i+1}, RK_{4i+2}, RK_{4i+3}) \leftarrow T$.

---

## 8. 18-Round Block Encryption and Decryption (CR-11, CR-12)

- **Reference:** RFC 6114 Section 5.1 (*Encryption/Decryption*) and Section 5.2 (*The Numbers of Rounds*).
- **Module:** `src/clefia/cipher.py` (`encrypt_block`, `decrypt_block`, `encrypt_block_with_schedule`, `decrypt_block_with_schedule`, `trace_encrypt_block`).
- **Encryption ($\mathrm{ENC}_{18}$):**
  1. Initial whitening on branches $1$ and $3$: $(T_0, T_1, T_2, T_3) \leftarrow (P_0, P_1 \oplus WK_0, P_2, P_3 \oplus WK_1)$.
  2. Apply 18-round $\mathrm{GFN}_{4,18}(RK_0, \dots, RK_{35}, T_0, T_1, T_2, T_3)$.
  3. Final whitening on branches $1$ and $3$: $(C_0, C_1, C_2, C_3) \leftarrow (T_0, T_1 \oplus WK_2, T_2, T_3 \oplus WK_3)$.
- **Decryption ($\mathrm{DEC}_{18}$):**
  1. Undo final whitening: $(T_0, T_1, T_2, T_3) \leftarrow (C_0, C_1 \oplus WK_2, C_2, C_3 \oplus WK_3)$.
  2. Apply $\mathrm{GFN}^{-1}_{4,18}(RK_0, \dots, RK_{35}, T_0, T_1, T_2, T_3)$.
  3. Undo initial whitening: $(P_0, P_1, P_2, P_3) \leftarrow (T_0, T_1 \oplus WK_0, T_2, T_3 \oplus WK_1)$.
- **Mandatory release-gate verification (RFC 6114 Appendix A & B):**
  - Key `ffeeddccbbaa99887766554433221100`, plaintext `000102030405060708090a0b0c0d0e0f` $\implies$ ciphertext `de2bf2fd9b74aacdf1298555459494fd`.
