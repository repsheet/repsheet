//! Actor canonicalization, using the same C code as the Redis and nginx modules.

use std::ffi::{CStr, c_char};

const RS_ACTOR_MAX: usize = 512;

#[repr(C)]
struct RsIp {
    family: u8,
    prefix: u8,
    addr: [u8; 16],
}

unsafe extern "C" {
    fn rs_actor_canonicalize(
        input: *const c_char,
        len: usize,
        out: *mut c_char,
        outlen: usize,
        ip: *mut RsIp,
        err: *mut *const c_char,
    ) -> usize;
}

/// Canonical form of `input` (`ip:10.0.0.0/8`, `session:abc`), or the reason
/// it is not a valid actor.
pub fn canonicalize(input: &str) -> Result<String, String> {
    let mut out = [0u8; RS_ACTOR_MAX + 1];
    let mut ip = RsIp {
        family: 0,
        prefix: 0,
        addr: [0; 16],
    };
    let mut err: *const c_char = std::ptr::null();
    // SAFETY: input/out are valid for the given lengths; err is set to a
    // static string on failure.
    let n = unsafe {
        rs_actor_canonicalize(
            input.as_ptr().cast(),
            input.len(),
            out.as_mut_ptr().cast(),
            out.len(),
            &mut ip,
            &mut err,
        )
    };
    if n == 0 {
        let msg = if err.is_null() {
            "invalid actor".to_string()
        } else {
            // SAFETY: err points at a NUL-terminated static string.
            unsafe { CStr::from_ptr(err) }
                .to_string_lossy()
                .into_owned()
        };
        return Err(msg);
    }
    Ok(String::from_utf8_lossy(&out[..n]).into_owned())
}

/// The type part of a canonical actor (`ip`, `session`, ...).
pub fn actor_type(canonical: &str) -> &str {
    canonical.split_once(':').map_or(canonical, |(t, _)| t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_like_the_module() {
        assert_eq!(canonicalize("1.2.3.4").unwrap(), "ip:1.2.3.4");
        assert_eq!(canonicalize("10.1.2.3/8").unwrap(), "ip:10.0.0.0/8");
        assert_eq!(
            canonicalize("::ffff:10.0.0.0/104").unwrap(),
            "ip:10.0.0.0/8"
        );
        assert_eq!(canonicalize("Session:AbC").unwrap(), "session:AbC");
        assert_eq!(canonicalize("2001:DB8::1").unwrap(), "ip:2001:db8::1");
    }

    #[test]
    fn rejects_invalid() {
        assert!(canonicalize("").is_err());
        assert!(canonicalize("1.2.3.4/33").is_err());
        assert!(canonicalize("bad type:x").is_err());
        assert!(canonicalize("session:a\nb").is_err());
        assert!(canonicalize(&"x".repeat(600)).is_err());
    }

    #[test]
    fn types() {
        assert_eq!(actor_type("ip:1.2.3.4"), "ip");
        assert_eq!(actor_type("api_key:a:b"), "api_key");
    }
}
