use argon2::{Algorithm, Argon2, Params, Version};

const M_COST: u32 = 32768;
const T_COST: u32 = 4;
const P_COST: u32 = 4;
const OUTPUT_LEN: usize = 32;

#[derive(Debug)]
pub struct KdfValue {
    value: Vec<u8>,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl KdfValue {
    /// CAUTION: Do NOT use this for normal password hashing!
    /// The result of hashing will always be same!
    /// This is only intended for generating enc keys, which must be always the same!
    pub fn new(password: &str) -> Self {
        let params = Params::new(M_COST, T_COST, P_COST, Some(OUTPUT_LEN)).unwrap();
        Self::new_with_params(password, params)
    }

    /// CAUTION: Do NOT use this for normal password hashing!
    /// The result of hashing will always be same!
    /// This is only intended for generating enc keys, which must be always the same!
    pub fn new_with_params(password: &str, params: Params) -> Self {
        let m_cost = params.m_cost();
        let t_cost = params.t_cost();
        let p_cost = params.p_cost();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut buf = [0u8; OUTPUT_LEN];
        argon2
            .hash_password_into(password.as_bytes(), b"00000000", &mut buf)
            .expect("password hash kdf to success");

        Self {
            value: buf.to_vec(),
            m_cost,
            t_cost,
            p_cost,
        }
    }

    /// Returns the correct enc key value for the EncKeyHeader
    pub fn enc_key_value(&self) -> String {
        format!("password${}${}${}", self.m_cost, self.t_cost, self.p_cost)
    }

    pub fn try_enc_key_to_params(enc_key_id: &str) -> Option<Params> {
        let (_, values) = enc_key_id.split_once("password$")?;
        let mut split = values.split('$');

        let m_cost = split.next()?.parse::<u32>().ok()?;
        let t_cost = split.next()?.parse::<u32>().ok()?;
        let p_cost = split.next()?.parse::<u32>().ok()?;

        // We must check the upper bounds here. If we assume the host is malicious, the Enc Key
        // params are basically attacker controlled. This means without a bound check, a payload
        // for a resource exhaustion attack could be crafted. We must not build the params in that
        // case because it would be trivial to get OOM killed.
        if m_cost > M_COST || t_cost > T_COST || p_cost > P_COST {
            return None;
        }

        let params = Params::new(m_cost, t_cost, p_cost, Some(OUTPUT_LEN)).ok()?;
        Some(params)
    }

    /// Returns the result of the inner hash value.
    pub fn value(self) -> Vec<u8> {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_enc_key_parse() {
        let password = "123";
        let kdf = KdfValue::new(password);
        let key_id = kdf.enc_key_value();

        let params = KdfValue::try_enc_key_to_params(&key_id).unwrap();
        let kdf_parsed = KdfValue::new_with_params(password, params);

        assert_eq!(kdf.value, kdf_parsed.value);
        assert_eq!(key_id, kdf_parsed.enc_key_value());
    }

    #[cfg(feature = "streaming")]
    #[test]
    fn test_kdf_enc_key_params_bounded() {
        // boundary: exactly at the generation constants must pass
        assert!(KdfValue::try_enc_key_to_params("password$32768$4$4").is_some());
        // anything above the constants is rejected (F-02 DoS payloads)
        assert!(KdfValue::try_enc_key_to_params("password$32769$4$4").is_none());
        assert!(KdfValue::try_enc_key_to_params("password$32768$5$4").is_none());
        assert!(KdfValue::try_enc_key_to_params("password$32768$4$5").is_none());
        assert!(KdfValue::try_enc_key_to_params("password$4294967295$4294967295$255").is_none());
    }
}
